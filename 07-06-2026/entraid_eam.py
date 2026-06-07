 
"""
EntraID External Authentication Method (EAM) blueprint — V3.

Behaviour:
  - "Insufficient data"  → allowed if ENROLLMENT_PASS_THROUGH=true, else re-render to collect more
  - "Profile got created" → allowed
  - "Legitimate user"     → allowed
  - Failures              → retry if RETRIES_ENABLED=true (up to MAX_BEHAVIOUR_ATTEMPTS), else denied immediately

Features:
  - js_url stored in session txn (reliable re-render)
  - Retry mechanism with fail_count (only when RETRIES_ENABLED=true)
  - DB insert on ebehaviory step (allowed + blocked + enrollment)
  - Dynamic error page (session_errors.html) for all error responses
  - Group switch logic removed
"""

import os
import time
import json
import base64
import hashlib
import logging
import threading
from html import escape as html_escape

from flask import Blueprint, request, jsonify, render_template, session
import jwt
import requests
from jwt import PyJWKClient
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from dotenv import load_dotenv

from shared.async_tasks import enqueue_behaviour_log
from shared.async_tasks import enqueue_alert_email
from shared.mail_helpers import fetch_tenant_mails, build_alert_payload

load_dotenv()
logger = logging.getLogger(__name__)

entraid_eam = Blueprint("entraid", __name__)

# ─── Config ───────────────────────────────────────────────
BASE_URL = os.getenv("ENTRAID_BASE_URL", "https://api357.cf.adapid.link").rstrip("/")
ISSUER = f"{BASE_URL}/idv/entraid/v2.0"

TENANT_API_URL = os.getenv("TENANT_API_URL", "")
TENANT_API_KEY = os.getenv("TENANT_API_KEY", "")
BEHAVIOUR_DOMAIN = os.getenv("BEHAVIOUR_DOMAIN", "").rstrip("/")
TENANT_CACHE_TTL = int(os.getenv("TENANT_CACHE_TTL", "3600"))

MAX_ATTEMPTS = int(os.getenv("MAX_BEHAVIOUR_ATTEMPTS", "3"))

# ─── Session lifetime ────────────────────────────────────
PERMANENT_SESSION_LIFETIME = int(os.getenv("PERMANENT_SESSION_LIFETIME", "600"))

# ─── Feature flags ────────────────────────────────────────
ENROLLMENT_PASS_THROUGH = os.getenv("ENROLLMENT_PASS_THROUGH", "true").strip().lower() == "true"
RETRIES_ENABLED = os.getenv("RETRIES_ENABLED", "true").strip().lower() == "true"

MSFT_OIDC_CONFIG_URL = os.getenv(
    "MSFT_OIDC_CONFIG_URL",
    "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
)

# ─── Signing material ────────────────────────────────────
with open("keys/private_key.pem", "rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

with open("keys/public_key.pem", "rb") as f:
    PUBLIC_KEY = serialization.load_pem_public_key(f.read())

with open("keys/cert.pem", "rb") as f:
    CERT_PEM_BYTES = f.read()
    CERT = x509.load_pem_x509_certificate(CERT_PEM_BYTES)

CERT_DER = CERT.public_bytes(serialization.Encoding.DER)
CERT_THUMBPRINT = hashlib.sha1(CERT_DER).digest()
X5T = base64.urlsafe_b64encode(CERT_THUMBPRINT).decode("utf-8").rstrip("=")
X5C = base64.b64encode(CERT_DER).decode("utf-8")
KEY_ID = X5T

# ─── Microsoft OIDC metadata ─────────────────────────────
_msft_oidc = requests.get(MSFT_OIDC_CONFIG_URL, timeout=10).json()
MSFT_ISSUER_TEMPLATE = _msft_oidc["issuer"]
MSFT_JWKS_URI = _msft_oidc["jwks_uri"]
MSFT_JWK_CLIENT = PyJWKClient(MSFT_JWKS_URI)


# ===========================================================================
# In-Memory Tenant Cache
# ===========================================================================

class TenantCache:
    def __init__(self, ttl_seconds=3600):
        self._cache = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def _make_key(self, entra_tenant_id, client_id):
        return f"{entra_tenant_id}:{client_id}"

    def get(self, entra_tenant_id, client_id):
        key = self._make_key(entra_tenant_id, client_id)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if time.time() > entry["expires_at"]:
                del self._cache[key]
                return None
            return entry["data"]

    def set(self, entra_tenant_id, client_id, data):
        key = self._make_key(entra_tenant_id, client_id)
        with self._lock:
            self._cache[key] = {
                "data": data,
                "expires_at": time.time() + self._ttl,
            }


_tenant_cache = TenantCache(ttl_seconds=TENANT_CACHE_TTL)


# ===========================================================================
# Tenant API Client
# ===========================================================================

def fetch_tenant_config(entra_tenant_id, client_id):
    cached = _tenant_cache.get(entra_tenant_id, client_id)
    if cached is not None:
        logger.debug("Tenant cache HIT | tid=%s", entra_tenant_id)
        return cached

    if not TENANT_API_URL:
        logger.error("TENANT_API_URL not configured")
        return None
    try:
        resp = requests.post(
            TENANT_API_URL,
            json={"entra_tenant_id": entra_tenant_id, "client_id": client_id},
            headers={"X-API-Key": TENANT_API_KEY},
            timeout=15,
        )
    except Exception as e:
        logger.error("Tenant API call failed: %s", e)
        return None

    if resp.status_code != 200:
        logger.error("Tenant API returned %d: %s", resp.status_code, resp.text)
        return None

    try:
        data = resp.json()
    except Exception as e:
        logger.error("Tenant API response not JSON: %s", e)
        return None

    if not data.get("isSuccess"):
        logger.warning("Tenant API isSuccess=false | tid=%s", entra_tenant_id)
        return None

    _tenant_cache.set(entra_tenant_id, client_id, data)
    return data


# ===========================================================================
# Helpers
# ===========================================================================

def b64url_uint(val):
    b = val.to_bytes((val.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def parse_requested_acr(claims_raw):
    default_acr = "knowledgeorpossessionorinherence"
    if not claims_raw:
        return default_acr
    try:
        claims_obj = json.loads(claims_raw)
        values = claims_obj.get("id_token", {}).get("acr", {}).get("values", [])
        if isinstance(values, list) and values:
            return values[0]
    except Exception:
        pass
    return default_acr


def parse_username_from_hint(hint_claims):
    return (
        hint_claims.get("preferred_username")
        or hint_claims.get("upn")
        or hint_claims.get("email")
        or hint_claims.get("sub")
    )


def call_behaviour_check(data, username, auth_key, tenant_id, core_url, client_secret):
    if not BEHAVIOUR_DOMAIN or not core_url:
        logger.error("Behaviour domain or core_url not configured")
        return None

    url = f"{BEHAVIOUR_DOMAIN}{core_url}"
    try:
        payload = {**data, "tenant_id": tenant_id}
        headers = {
            "Content-Type": "application/json",
            "X-Secret-Key": client_secret,
            "Auth-Key": auth_key,
        }
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        if resp.status_code != 200:
            logger.error(
                "Behaviour API returned %d | tenant=%s | body=%s",
                resp.status_code, tenant_id, resp.text[:500],
            )
            return None
        return resp.json()
    except Exception as e:
        logger.error("Behaviour API failed | tenant=%s | error=%s", tenant_id, e)
        return None


def _rebuild_js_url(txn):
    """Read js_url directly from session — no cache dependency."""
    if not txn:
        return ""
    return txn.get("js_url", "")


def _safe_redirect_html(action, fields):
    """
    Build an auto-submitting form with properly escaped values.
    `fields` is a dict of {name: value} for hidden inputs.
    """
    safe_action = html_escape(action, quote=True)
    inputs = "\n".join(
        f'<input type="hidden" name="{html_escape(k, quote=True)}" value="{html_escape(str(v), quote=True)}" />'
        for k, v in fields.items()
    )
    return f"""
        <html>
        <body onload="document.forms[0].submit()">
        <form method="POST" action="{safe_action}">
        {inputs}
        <noscript><button type="submit">Continue</button></noscript>
        </form>
        </body>
        </html>
    """


# ===========================================================================
# Discover1y
# ===========================================================================

@entraid_eam.route(
    "/idv/entraid/v2.0/.well-known/openid-configuration", methods=["GET"]
)
def entraid_discovery():
    config = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{BASE_URL}/idv/entraid/api/Authorize",
        "jwks_uri": f"{BASE_URL}/idv/entraid/.well-known/jwks",
        "response_types_supported": ["id_token"],
        "response_modes_supported": ["form_post"],
        "grant_types_supported": ["implicit"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid"],
        "claims_supported": [
            "email", "acr", "amr", "sub", "nonce", "iss", "aud", "iat", "exp",
        ],
        "subject_types_supported": ["public"],
        "claim_types_supported": ["normal"],
        "SigningKeys": [],
    }
    return jsonify(config)


# ===========================================================================
# JWKS
# ===========================================================================

@entraid_eam.route("/idv/entraid/.well-known/jwks", methods=["GET"])
def entraid_jwks():
    numbers = PUBLIC_KEY.public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "kid": KEY_ID,
        "x5t": KEY_ID,
        "alg": "RS256",
        "n": b64url_uint(numbers.n),
        "e": b64url_uint(numbers.e),
        "x5c": [X5C],
    }
    return jsonify({"keys": [jwk]})


# ===========================================================================
# Authorize
# ===========================================================================

from shared.tenant_discovery import get_tenant_by_entra_tid

@entraid_eam.route("/idv/entraid/api/Authorize", methods=["POST"])
def entraid_authorize():
    args = request.form
    client_id = args.get("client_id", "")
    redirect_uri = args.get("redirect_uri", "")
    state = args.get("state", "")
    nonce = args.get("nonce", "")
    scope = args.get("scope", "")
    response_type = args.get("response_type", "")
    response_mode = args.get("response_mode", "")
    login_hint = args.get("login_hint", "")
    id_token_hint = args.get("id_token_hint", "")
    claims_raw = args.get("claims", "")
    client_request_id = args.get("client-request-id", "")

    # Basic OIDC Validation
    if response_type.lower() != "id_token":
        return render_template("session_errors.html", error_title="Unsupported Request", error_message="Unsupported response_type."), 400
    if response_mode.lower() != "form_post":
        return render_template("session_errors.html", error_title="Unsupported Request", error_message="Unsupported response_mode."), 400
    if scope != "openid":
        return render_template("session_errors.html", error_title="Unsupported Request", error_message="Unsupported scope."), 400
    if not id_token_hint:
        return render_template("session_errors.html", error_title="Missing Data", error_message="Missing id_token_hint. Please restart the login process."), 400

    # Step 1: Preliminary decode to extract Microsoft Tenant ID (tid)
    try:
        signing_key = MSFT_JWK_CLIENT.get_signing_key_from_jwt(id_token_hint)
        raw_claims = jwt.decode(
            id_token_hint,
            signing_key.key,
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "verify_aud": False,
                "verify_exp": True,
                "verify_iat": True,
            },
            leeway=60,
        )
    except jwt.ExpiredSignatureError:
        return render_template("session_errors.html", error_title="Request Expired", error_message="Your login request has expired. Please try again."), 400
    except Exception as e:
        logger.warning("Pre-verification failed: %s", e)
        return render_template("session_errors.html", error_title="Invalid Request", error_message="Unable to verify the request source."), 400

    entra_tenant_id = raw_claims.get("tid")
    if not entra_tenant_id:
        return render_template("session_errors.html", error_title="Invalid Token", error_message="Invalid token context. Tenant identifier missing."), 400

    # Step 2: Fetch tenant config
    tenant_config = fetch_tenant_config(entra_tenant_id, client_id)
    if not tenant_config:
        logger.warning("Tenant core config not found | tid=%s", entra_tenant_id)
        return render_template("session_errors.html", error_title="Unknown Tenant", error_message="Your organization's configuration could not be found."), 400

    adapid_tenant_id = tenant_config.get("adapID_tenant_id", "")
    entra_app_id = tenant_config.get("entra_app_id", "")
    db_name = tenant_config.get("db_name", "")
    core_url = tenant_config.get("core_url", "")
    js_url = tenant_config.get("js_url", "")
    adapid_client_secret = tenant_config.get("adapID_client_secret", "")

    # Step 3: Full JWT validation using audience from tenant config
    try:
        hint_claims = jwt.decode(
            id_token_hint,
            signing_key.key,
            algorithms=["RS256"],
            audience=entra_app_id,
            issuer=f"https://login.microsoftonline.com/{entra_tenant_id}/v2.0",
            options={"verify_signature": True},
        )
    except jwt.ExpiredSignatureError:
        logger.warning("id_token_hint expired")
        return render_template("session_errors.html", error_title="Request Expired", error_message="Your login request has expired. Please restart the login process."), 400
    except jwt.InvalidTokenError as e:
        logger.warning("id_token_hint validation failed: %s", e)
        return render_template("session_errors.html", error_title="Validation Failed", error_message="Security validation failed. Please restart the login process."), 400

    subject = hint_claims.get("sub")
    if not subject:
        return render_template("session_errors.html", error_title="Missing Identifier", error_message="Missing user identifier in token."), 400

    username = parse_username_from_hint(hint_claims)

    # Step 4: ACR handling
    requested_acr = parse_requested_acr(claims_raw)
    supported_acrs = ["possession", "knowledgeorpossessionorinherence", "possessionorinherence", "any"]
    if requested_acr not in supported_acrs:
        logger.warning("Unsupported ACR: %s — defaulting", requested_acr)
        requested_acr = "possessionorinherence"

    # Step 5: Build full Behavioral JS URL
    full_js_url = ""
    if BEHAVIOUR_DOMAIN and js_url:
        full_js_url = f"{BEHAVIOUR_DOMAIN}{js_url}"

    # Step 6: Save to session
    session.permanent = True
    session["entraid_txn"] = {
        "adapid_tenant_id": adapid_tenant_id,
        "adapid_client_secret": adapid_client_secret,
        "core_url": core_url,
        "db_name": db_name,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "js_url": full_js_url,
        "state": state,
        "nonce": nonce,
        "requested_acr": requested_acr,
        "subject": subject,
        "username": username,
        "hint_tid": entra_tenant_id,
        "hint_oid": hint_claims.get("oid"),
        "claims_raw": claims_raw,
        "client_request_id": client_request_id,
        "login_hint": login_hint,
        "response_mode": response_mode,
        "response_type": response_type,
        "fail_count": 0,
    }

    # Step 7: Render collection page
    return render_template(
        "behavior.html",
        login_hint=username,
        error_message=None,
        action_url="/idv/entraid/api/Complete",
        js_url=full_js_url,
    )


# ===========================================================================
# Complete
# ===========================================================================

@entraid_eam.route("/idv/entraid/api/Complete", methods=["POST"])
def entraid_complete():
    txn = session.get("entraid_txn")
    if not txn:
        return "<h1>Session expired or no transaction found.</h1>", 400

    # ── Extract transaction values ──
    username             = txn.get("username", "")
    subject              = txn.get("subject", "")
    redirect_uri         = txn.get("redirect_uri", "")
    state                = txn.get("state", "")
    nonce                = txn.get("nonce", "")
    client_id            = txn.get("client_id", "")
    requested_acr        = txn.get("requested_acr", "")
    adapid_tenant_id     = txn.get("adapid_tenant_id", "")
    adapid_client_secret = txn.get("adapid_client_secret", "")
    core_url             = txn.get("core_url", "")
    db_name              = txn.get("db_name", "")
    hint_tid             = txn.get("hint_tid", "")              # ← NEW: needed for alert emails
    client_request_id    = txn.get("client_request_id", state)  # ← NEW: needed for DB record
    fail_count           = txn.get("fail_count", 0)

    user_input = request.form.get("hiddenField", "")
    if not user_input:
        return render_template(
            "sentence.html",
            login_hint=username,
            action_url="/idv/entraid/api/Complete",
            error_message="No behavioral data received. Please try again.",
            js_url=_rebuild_js_url(txn),
        )

    try:
        parsed = json.loads(user_input)
    except json.JSONDecodeError:
        return render_template(
            "sentence.html",
            login_hint=username,
            action_url="/idv/entraid/api/Complete",
            error_message="Invalid data format. Please try again.",
            js_url=_rebuild_js_url(txn),
        )

    behaviour_data = parsed.get("behaviourData", {})
    authkey        = parsed.get("authkey", "")
    if not behaviour_data or not authkey:
        return render_template(
            "sentence.html",
            login_hint=username,
            action_url="/idv/entraid/api/Complete",
            error_message="Missing behavioral data. Please try again.",
            js_url=_rebuild_js_url(txn),
        )

    # ── Behaviour API call ──
    timestamp = int(time.time())
    core = call_behaviour_check(
        data=behaviour_data,
        username=username,
        auth_key=authkey,
        tenant_id=adapid_tenant_id,
        core_url=core_url,
        client_secret=adapid_client_secret,
    )

    if core is None:
        return render_template(
            "sentence.html",
            login_hint=username,
            action_url="/idv/entraid/api/Complete",
            error_message="Unable to verify behavioral data. Please try again.",
            js_url=_rebuild_js_url(txn),
        )

    # ── Outcome variables (set by the stair, acted on after) ──
    behavioural_status = "Unknown"
    user_type          = "Unknown"
    is_legitimate      = False
    error_message      = None
    needs_alert        = False
    alert_reason       = ""
    already_logged     = False

    # ══════════════════════════════════════════════════════════════════════
    # Branch A: message-based response (enrollment / profile creation)
    # ══════════════════════════════════════════════════════════════════════
    if "message" in core:
        message = core.get("message", "")

        if message == "Insufficient data to create profile":
            record = {
                "idp_transaction_id":  client_request_id,
                "username":            username,
                "message":             message,
                "idp":                 "entraid",
                "behavioral_status":   "Insufficient data",
                "combined_risk_score": core.get("combined_risk_score", 0),
                "behavior_success":    core.get("isSuccess", "False"),
                "user_type":           "New",
                "auth_time_iso":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
            }
            enqueue_behaviour_log(record, db_name=db_name)
            already_logged = True

            if ENROLLMENT_PASS_THROUGH:
                logger.info(
                    "Insufficient data — ALLOWED (pass-through) | tenant=%s | user=%s",
                    adapid_tenant_id, username,
                )
                is_legitimate = True
            else:
                logger.info(
                    "Insufficient data — re-rendering | tenant=%s | user=%s",
                    adapid_tenant_id, username,
                )
                return render_template(
                    "sentence.html",
                    login_hint=username,
                    action_url="/idv/entraid/api/Complete",
                    error_message="Please continue typing to complete your profile setup.",
                    js_url=_rebuild_js_url(txn),
                )

        elif message == "Profile got created":
            behavioural_status = "Profile created"
            user_type          = "New"
            is_legitimate      = True
            logger.info(
                "Profile created — allowed | tenant=%s | user=%s",
                adapid_tenant_id, username,
            )

        else:
            error_message = f"Authentication failed: {message}."

    # ══════════════════════════════════════════════════════════════════════
    # Branch B: behavioral biometrics
    # ══════════════════════════════════════════════════════════════════════
    elif "behavioral_biometrics" in core:
        bb = core.get("behavioral_biometrics", "")
        bc = core.get("behavioral_check", "no")

        if bb == "Legitimate user" and bc == "yes":
            behavioural_status = "Legitimate user"
            user_type          = "legitimate"
            is_legitimate      = True
            logger.info(
                "ALLOWED | tenant=%s | user=%s | risk=%s",
                adapid_tenant_id, username, core.get("combined_risk_score"),
            )

        elif bb == "Step up" and bc == "no":
            behavioural_status = "Step up required"
            user_type          = "suspicious"
            error_message      = "Additional verification required. Suspicious behavior detected."
            needs_alert        = True
            alert_reason       = "Step up required"
            logger.warning(
                "BLOCKED — step up | tenant=%s | user=%s | risk=%s",
                adapid_tenant_id, username, core.get("combined_risk_score"),
            )

        else:
            behavioural_status = bb
            user_type          = "unknown"
            error_message      = "Login failed. Unusual behavior detected."
            needs_alert        = True
            alert_reason       = f"Unusual — {bb}"
            logger.warning(
                "BLOCKED — unusual | tenant=%s | user=%s | status=%s",
                adapid_tenant_id, username, bb,
            )

    # ══════════════════════════════════════════════════════════════════════
    # Branch C: legacy user_type
    # ══════════════════════════════════════════════════════════════════════
    elif "user_type" in core:
        user_type = core.get("user_type", "")
        if user_type == "legitimate":
            behavioural_status = "Legitimate user"
            is_legitimate      = True
            logger.info(
                "ALLOWED — legacy | tenant=%s | user=%s",
                adapid_tenant_id, username,
            )
        else:
            behavioural_status = f"User type: {user_type}"
            error_message      = "Login failed. Intruder detected."
            needs_alert        = True
            alert_reason       = f"Intruder — {user_type}"
            logger.warning(
                "BLOCKED — intruder | tenant=%s | user=%s | type=%s",
                adapid_tenant_id, username, user_type,
            )

    else:
        error_message = "Unable to validate behavioral data."
        logger.error(
            "Missing validation fields | tenant=%s | core=%s",
            adapid_tenant_id, core,
        )

    # ══════════════════════════════════════════════════════════════════════
    # After stair: DB insert (if not already done by an early-return branch)
    # ══════════════════════════════════════════════════════════════════════
    temp_timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
    if not already_logged:
        record = {
            "idp_transaction_id":  client_request_id,
            "username":            username,
            "message":             core.get("message", ""),
            "idp":                 "entraid",
            "behavioral_status":   behavioural_status,
            "combined_risk_score": core.get("combined_risk_score", 0),
            "behavior_success":    core.get("isSuccess", "False"),
            "user_type":           user_type,
            "auth_time_iso":       temp_timestamp,
        }
        enqueue_behaviour_log(record, db_name=db_name)

    # ── Alert email (conditional) ──
    if needs_alert:
        alert_recipients = fetch_tenant_mails(hint_tid)
        if alert_recipients:
            enqueue_alert_email(
                alert=build_alert_payload(
                    username, adapid_tenant_id, alert_reason,
                    core.get("combined_risk_score", 0), temp_timestamp,
                ),
                recipients=alert_recipients,
            )
        else:
            logger.warning("No alert recipients configured | tenant=%s", adapid_tenant_id)

    # ══════════════════════════════════════════════════════════════════════
    # Failure handling
    # ══════════════════════════════════════════════════════════════════════
    if not is_legitimate:
        fail_count += 1
        txn["fail_count"] = fail_count
        session["entraid_txn"] = txn

        deny_immediately = (not RETRIES_ENABLED) or (fail_count >= MAX_ATTEMPTS)

        if deny_immediately:
            session.pop("entraid_txn", None)

            if RETRIES_ENABLED:
                denial_reason = f"Behavioral verification failed after {MAX_ATTEMPTS} attempt(s)."
            else:
                denial_reason = error_message or "Behavioral verification failed."

            logger.warning(
                "Access DENIED | retries_enabled=%s | attempt=%d/%d | tenant=%s | user=%s",
                RETRIES_ENABLED, fail_count, MAX_ATTEMPTS, adapid_tenant_id, username,
            )

            return _safe_redirect_html(redirect_uri, {
                "error": "access_denied",
                "error_description": denial_reason,
                "state": state,
            })

        attempts_left = MAX_ATTEMPTS - fail_count
        logger.warning(
            "Attempt %d/%d failed | tenant=%s | user=%s",
            fail_count, MAX_ATTEMPTS, adapid_tenant_id, username,
        )
        return render_template(
            "sentence.html",
            login_hint=username,
            action_url="/idv/entraid/api/Complete",
            error_message=(
                f"{error_message} "
                f"(Attempt {fail_count}/{MAX_ATTEMPTS} — {attempts_left} remaining)"
            ),
            js_url=_rebuild_js_url(txn),
        )

    # ══════════════════════════════════════════════════════════════════════
    # Success — generate JWT and redirect back to Entra
    # ══════════════════════════════════════════════════════════════════════
    now = int(time.time())
    id_token_claims = {
        "iss": ISSUER,
        "aud": client_id,
        "sub": subject,
        "iat": now,
        "exp": now + 300,
        "nonce": nonce,
        "acr": requested_acr,
        "amr": ["pop"],
        "email": username,
        "preferred_username": username,
        "auth_time": now,
    }

    id_token = jwt.encode(
        id_token_claims,
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID, "typ": "JWT"},
    )

    logger.info("JWT generated | tenant=%s | user=%s", adapid_tenant_id, username)

    session.pop("entraid_txn", None)

    return _safe_redirect_html(redirect_uri, {
        "id_token": id_token,
        "state": state,
    })