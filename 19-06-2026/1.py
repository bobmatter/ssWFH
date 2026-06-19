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




























# import os
# import sys
# import time
# import logging
# import threading
# import subprocess
# from logging.handlers import RotatingFileHandler

# import psutil
# import webview

# # =============================
# # CONFIG
# # =============================
# APPDATA_DIR = os.path.join(
#     os.getenv("LOCALAPPDATA") or os.path.expanduser("~"), "AppLockerrrr"
# )
# LOG_DIR = os.path.join(APPDATA_DIR, "logs")

# SERVER_BASE = "https://api357.cf.adapid.link"  # <-- set your server base URL here
# GET_HTML_URL = f"{SERVER_BASE}/idv/adapidDesktop/api/getHTML"
# COMPLETE_URL = f"{SERVER_BASE}/idv/adapidDesktop/api/complete"

# # Apps to lock. Key = lowercase process name, value = friendly display name.
# LOCKED_APPS = {
#     # "notion.exe": "Notion",
#     "chrome.exe": "Google Chrome",
#     "ms-teams.exe": "Microsoft Teams",
#     # "notepad.exe": "Notepad",
# }

# # How long the verification window may stay open before we give up (seconds).
# VERIFY_TIMEOUT = 300

# # Track which apps have already passed verification this session.
# is_verified = {app: False for app in LOCKED_APPS}


# # =============================
# # LOGGING
# # =============================
# def setup_logging() -> logging.Logger:
#     """
#     Configure a rotating file logger that works the same whether the script
#     is run normally or frozen by PyInstaller (including --noconsole builds,
#     where sys.stdout is None and print() would otherwise crash).

#     Logs go to:  %LOCALAPPDATA%\\AppLockerrrr\\logs\\applocker.log
#     """
#     os.makedirs(LOG_DIR, exist_ok=True)
#     log_file = os.path.join(LOG_DIR, "applocker.log")

#     logger = logging.getLogger("AppLocker")
#     logger.setLevel(logging.DEBUG)

#     # Avoid adding duplicate handlers if setup_logging() is called twice.
#     if logger.handlers:
#         return logger

#     fmt = logging.Formatter(
#         "%(asctime)s | %(levelname)-7s | pid=%(process)d | %(message)s",
#         "%Y-%m-%d %H:%M:%S",
#     )

#     # Rotating file handler: 2 MB per file, keep 5 backups.
#     fh = RotatingFileHandler(
#         log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
#     )
#     fh.setLevel(logging.DEBUG)
#     fh.setFormatter(fmt)
#     logger.addHandler(fh)

#     # Console handler only if we actually have a console (script / one-folder
#     # console build). In a windowed exe sys.stdout is None, so we skip it.
#     try:
#         if sys.stdout is not None:
#             ch = logging.StreamHandler(sys.stdout)
#             ch.setLevel(logging.INFO)
#             ch.setFormatter(fmt)
#             logger.addHandler(ch)
#     except Exception:
#         pass

#     logger.info("=" * 60)
#     logger.info("Logger initialised. Writing to: %s", log_file)
#     logger.info("Frozen (PyInstaller): %s", getattr(sys, "frozen", False))
#     if not SERVER_BASE:
#         logger.warning("SERVER_BASE is empty — verification URLs will be invalid.")
#     return logger


# # =============================
# # VERIFICATION WINDOW (runs in its own process)
# # =============================
# def run_verification_window(app_name: str) -> bool:
#     """
#     Open a pywebview window that loads the adapID verification page.

#     This runs in a *dedicated process* (see the --verify branch in __main__),
#     which is the key fix: webview.start() can only be called once per process,
#     so giving each verification its own process lets us verify any number of
#     apps reliably.

#     Returns True if verification passed (also signalled via exit code).
#     """
#     logger = setup_logging()
#     result = {"passed": False, "done": False}

#     # Re-evaluated on a timer so we catch the success/failure state even when
#     # the page updates *after* it first loads (the old single-injection
#     # approach missed that).
#     CHECK_JS = """
#     (function() {
#         try {
#             var bodyText = document.body ? document.body.innerText : '';
#             try {
#                 var data = JSON.parse(bodyText);
#                 if (data && data.status === 'success') return 'PASS';
#                 if (data && data.status === 'failed')  return 'FAIL';
#             } catch (e) {}
#             if (bodyText.indexOf('Access Denied') !== -1) return 'FAIL';
#             if (bodyText.indexOf('Verification Successful') !== -1) return 'PASS';
#         } catch (e) {}
#         return 'PENDING';
#     })();
#     """

#     class Api:
#         """The page can also resolve directly via window.pywebview.api.done()."""

#         def done(self, passed):
#             result["passed"] = bool(passed)
#             result["done"] = True
#             logger.info("Page called done(passed=%s) for %s", passed, app_name)
#             try:
#                 window.destroy()
#             except Exception:
#                 pass

#     api = Api()
#     verify_url = f"{GET_HTML_URL}?app={app_name}"
#     logger.info("Opening verification window for '%s' -> %s", app_name, verify_url)

#     window = webview.create_window(
#         f"adapID — Verify access to {LOCKED_APPS.get(app_name, app_name)}",
#         url=verify_url,
#         js_api=api,
#         width=520,
#         height=600,
#         resizable=False,
#         on_top=True,
#     )

#     def poll():
#         deadline = time.time() + VERIFY_TIMEOUT
#         while not result["done"] and time.time() < deadline:
#             try:
#                 state = window.evaluate_js(CHECK_JS)
#             except Exception:
#                 # Window probably closed / not ready yet.
#                 state = None

#             if state == "PASS":
#                 result["passed"] = True
#                 result["done"] = True
#                 logger.info("Verification PASSED for %s", app_name)
#                 break
#             if state == "FAIL":
#                 result["passed"] = False
#                 result["done"] = True
#                 logger.info("Verification FAILED for %s", app_name)
#                 break
#             time.sleep(1)

#         if not result["done"]:
#             logger.warning("Verification timed out for %s", app_name)
#             result["done"] = True

#         try:
#             window.destroy()
#         except Exception:
#             pass

#     # Start polling once the page has loaded.
#     window.events.loaded += lambda: threading.Thread(
#         target=poll, daemon=True
#     ).start()

#     # Blocks until the window is destroyed.
#     webview.start(debug=False)

#     logger.info(
#         "Verification window closed for %s. passed=%s", app_name, result["passed"]
#     )
#     return result["passed"]


# def request_verification(app_name: str) -> bool:
#     """
#     Launch the verification window in a separate process and wait for it.
#     Exit code 0 == passed, anything else == not passed.
#     """
#     logger = logging.getLogger("AppLocker")

#     cmd = [sys.executable]
#     if not getattr(sys, "frozen", False):
#         # Running as a normal script: pass the script path to python.
#         cmd.append(os.path.abspath(__file__))
#     cmd += ["--verify", app_name]

#     logger.info("Spawning verification process: %s", cmd)
#     try:
#         completed = subprocess.run(cmd)
#         passed = completed.returncode == 0
#         logger.info(
#             "Verification process for %s exited with code %s (passed=%s)",
#             app_name,
#             completed.returncode,
#             passed,
#         )
#         return passed
#     except Exception:
#         logger.exception("Verification subprocess failed for %s", app_name)
#         return False


# # =============================
# # RELAUNCH
# # =============================
# def relaunch_app(app_name: str, exe_path: str) -> None:
#     """Relaunch a previously-terminated app as reliably as possible on Windows."""
#     logger = logging.getLogger("AppLocker")

#     if not exe_path or not os.path.exists(exe_path):
#         logger.warning(
#             "Cannot relaunch %s: exe path missing or invalid (%r)",
#             app_name,
#             exe_path,
#         )
#         return

#     logger.info("Relaunching %s from %s", app_name, exe_path)
#     # os.startfile uses ShellExecute and is the most reliable way to start
#     # a Windows app (handles launchers, working dirs, elevation prompts, etc.).
#     try:
#         os.startfile(exe_path)  # noqa: Windows-only, which is fine here.
#         return
#     except Exception:
#         logger.exception("os.startfile failed for %s, falling back to Popen", app_name)

#     try:
#         subprocess.Popen([exe_path], cwd=os.path.dirname(exe_path) or None)
#     except Exception:
#         logger.exception("Popen relaunch also failed for %s", app_name)


# # =============================
# # MONITOR LOOP
# # =============================
# def monitor() -> None:
#     """Continuously watch for locked apps being launched."""
#     logger = logging.getLogger("AppLocker")
#     logger.info("Monitor started. Press Ctrl+C to stop.")
#     logger.info("Watching: %s", list(LOCKED_APPS.keys()))

#     while True:
#         for proc in psutil.process_iter(["name", "exe"]):
#             try:
#                 name = (proc.info["name"] or "").lower()
#                 if name not in LOCKED_APPS:
#                     continue

#                 if is_verified[name]:
#                     continue

#                 exe_path = proc.info["exe"] or ""
#                 logger.info(
#                     "Caught %s (pid=%s) — terminating and showing verification.",
#                     name,
#                     proc.pid,
#                 )

#                 try:
#                     proc.terminate()
#                     proc.wait(timeout=5)
#                     logger.debug("Terminated %s", name)
#                 except Exception:
#                     logger.exception("Problem terminating %s", name)

#                 # Blocks until the verification process finishes.
#                 passed = request_verification(name)

#                 if passed:
#                     is_verified[name] = True
#                     relaunch_app(name, exe_path)
#                 else:
#                     logger.info("Not relaunching %s (verification not passed).", name)

#             except (psutil.NoSuchProcess, psutil.AccessDenied):
#                 pass
#             except Exception:
#                 logger.exception("Error handling a process")

#         time.sleep(1)


# # =============================
# # ENTRY POINT
# # =============================
# if __name__ == "__main__":
#     # Child mode: open one verification window and report via exit code.
#     if len(sys.argv) >= 3 and sys.argv[1] == "--verify":
#         app_arg = sys.argv[2]
#         ok = run_verification_window(app_arg)
#         sys.exit(0 if ok else 1)

#     # Parent mode: run the monitor.
#     log = setup_logging()
#     os.makedirs(APPDATA_DIR, exist_ok=True)
#     try:
#         monitor()
#     except KeyboardInterrupt:
#         log.info("Ctrl+C detected. Stopping monitor gracefully...")
#         try:
#             sys.exit(0)
#         except SystemExit:
#             os._exit(0)
#     except Exception:
#         log.exception("Fatal error in monitor — exiting.")
#         os._exit(1)




import os
import sys
import time
import logging
import threading
from logging.handlers import RotatingFileHandler
import getpass
import psutil
import webview

# =============================
# CONFIG
# =============================
APPDATA_DIR = os.path.join(
    os.getenv("LOCALAPPDATA") or os.path.expanduser("~"), "AppLockerrrr"
)
LOG_DIR = os.path.join(APPDATA_DIR, "logs")

# IMPORTANT: must be a full URL with scheme + host, e.g. "https://your-server.com"
# If this is empty the verification page has nothing to load and the window
# will just sit there blank.
SERVER_BASE = "https://api357.cf.adapid.link"
GET_HTML_URL = f"{SERVER_BASE}/idv/adapidDesktop/api/getHTML"
COMPLETE_URL = f"{SERVER_BASE}/idv/adapidDesktop/api/complete"
username=getpass.getuser()
# Apps to lock. Key = lowercase process name, value = friendly display name.
LOCKED_APPS = {
    "notion.exe": "Notion",
    "chrome.exe": "Google Chrome",
    "ms-teams.exe": "Microsoft Teams",
    "notepad.exe": "Notepad",
}

# How long a verification window may stay open before we give up (seconds).
VERIFY_TIMEOUT = 300

# Track which apps have already passed verification this session.
is_verified = {app: False for app in LOCKED_APPS}


# =============================
# LOGGING
# =============================
def setup_logging() -> logging.Logger:
    """Rotating file logger that also works in a --noconsole PyInstaller build."""
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, "applocker.log")

    logger = logging.getLogger("AppLocker")
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    fh = RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    try:
        if sys.stdout is not None:  # None in a windowed exe -> skip console handler
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.INFO)
            ch.setFormatter(fmt)
            logger.addHandler(ch)
    except Exception:
        pass

    logger.info("=" * 60)
    logger.info("Logger initialised. Writing to: %s", log_file)
    logger.info("Frozen (PyInstaller): %s", getattr(sys, "frozen", False))
    if not SERVER_BASE:
        logger.error(
            "SERVER_BASE is EMPTY. Verification pages cannot load. Set SERVER_BASE "
            "to a full URL like 'https://your-server.com'."
        )
    return logger


# =============================
# VERIFICATION (runs on the monitor worker thread, NOT a subprocess)
# =============================
def show_verification(app_name: str) -> bool:
    """
    Create a verification window on demand and block (this thread only) until it
    resolves. Safe to call repeatedly because webview.start() was already called
    once on the main thread; here we only create/destroy child windows.
    """
    logger = logging.getLogger("AppLocker")

    result = {"passed": False}
    closed = threading.Event()

    CHECK_JS = """
    (function() {
        try {
            var t = document.body ? document.body.innerText : '';
            try {
                var d = JSON.parse(t);
                if (d && d.status === 'success') return 'PASS';
                if (d && d.status === 'failed')  return 'FAIL';
            } catch (e) {}
            if (t.indexOf('Access Denied') !== -1) return 'FAIL';
            if (t.indexOf('Verification Successful') !== -1) return 'PASS';
        } catch (e) {}
        return 'PENDING';
    })();
    """

    class Api:
        """The page may also resolve directly via window.pywebview.api.done()."""

        def done(self, passed):
            result["passed"] = bool(passed)
            logger.info("Page called done(passed=%s) for %s", passed, app_name)
            _destroy()

    def _destroy():
        try:
            win.destroy()
        except Exception:
            pass
    verify_url = f"{GET_HTML_URL}?app={app_name}&username={username}"#user also i want 
    logger.info("Creating verification window for '%s' -> %s", app_name, verify_url)

    win = webview.create_window(
        f"adapID -- Verify access to {LOCKED_APPS.get(app_name, app_name)}",
        url=verify_url,
        js_api=Api(),
        width=520,
        height=600,
        resizable=False,
        on_top=True,
    )
    win.events.closed += lambda: closed.set()

    # Poll the page until it resolves, the user closes it, or we time out.
    deadline = time.time() + VERIFY_TIMEOUT
    last_state = None
    while not closed.is_set() and time.time() < deadline:
        try:
            state = win.evaluate_js(CHECK_JS)
        except Exception:
            state = None  # window not ready / already gone

        if state != last_state and state is not None:
            logger.debug("Verification state for %s: %s", app_name, state)
            last_state = state

        if state == "PASS":
            result["passed"] = True
            logger.info("Verification PASSED for %s", app_name)
            _destroy()
            break
        if state == "FAIL":
            logger.info("Verification FAILED for %s", app_name)
            _destroy()
            break

        time.sleep(1)

    if not closed.is_set():
        if time.time() >= deadline:
            logger.warning("Verification TIMED OUT for %s", app_name)
        _destroy()

    closed.wait(timeout=5)
    logger.info("Verification window closed for %s. passed=%s", app_name, result["passed"])
    return result["passed"]


# =============================
# RELAUNCH
# =============================
def relaunch_app(app_name: str, exe_path: str) -> None:
    """Relaunch a previously-terminated app as reliably as possible on Windows."""
    logger = logging.getLogger("AppLocker")

    if not exe_path or not os.path.exists(exe_path):
        logger.warning(
            "Cannot relaunch %s: exe path missing/invalid (%r)", app_name, exe_path
        )
        return

    logger.info("Relaunching %s from %s", app_name, exe_path)
    try:
        os.startfile(exe_path)  # Windows-only; most reliable launcher.
        return
    except Exception:
        logger.exception("os.startfile failed for %s, trying Popen", app_name)

    try:
        import subprocess

        subprocess.Popen([exe_path], cwd=os.path.dirname(exe_path) or None)
    except Exception:
        logger.exception("Popen relaunch also failed for %s", app_name)


# =============================
# MONITOR (runs on a worker thread spawned by webview.start)
# =============================
def monitor() -> None:
    logger = logging.getLogger("AppLocker")
    logger.info("Monitor started.")
    logger.info("Watching: %s", list(LOCKED_APPS.keys()))

    while True:
        for proc in psutil.process_iter(["name", "exe"]):
            try:
                name = (proc.info["name"] or "").lower()
                if name not in LOCKED_APPS or is_verified[name]:
                    continue

                exe_path = proc.info["exe"] or ""
                logger.info(
                    "Caught %s (pid=%s) -- terminating and verifying.", name, proc.pid
                )

                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                    logger.debug("Terminated %s", name)
                except Exception:
                    logger.exception("Problem terminating %s", name)

                # Blocks this worker thread only; the GUI loop keeps running.
                passed = show_verification(name)

                if passed:
                    is_verified[name] = True
                    relaunch_app(name, exe_path)
                else:
                    logger.info("Not relaunching %s (verification not passed).", name)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                logger.exception("Error handling a process")

        time.sleep(1)


# =============================
# ENTRY POINT
# =============================
if __name__ == "__main__":
    log = setup_logging()
    os.makedirs(APPDATA_DIR, exist_ok=True)

    try:
        # A single hidden "master" window keeps the GUI event loop alive so we
        # can create verification windows on demand. webview.start() runs the
        # loop on the main thread (required) and runs monitor() in a worker
        # thread. This is the key fix: start() is called exactly once.
        webview.create_window(
            "AppLocker (background)",
            html="<html><body style='font-family:sans-serif'>AppLocker is running.</body></html>",
            hidden=True,
        )
        webview.start(monitor, debug=False)
    except KeyboardInterrupt:
        log.info("Ctrl+C detected. Stopping...")
        os._exit(0)
    except Exception:
        log.exception("Fatal error -- exiting.")
        os._exit(1)
        
        
        
        
        
        
        
        
        
        



















<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Identity Verification</title>
    <style>
        *,
        *::before,
        *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
            -webkit-font-smoothing: antialiased;
        }

        .adapdIDWrapper {
            height: 100vh;
            width: 100vw;
            position: fixed;
            display: flex;
            justify-content: center;
            align-items: center;
            background: #f5f5f5;
            -webkit-user-select: none;
            -ms-user-select: none;
            user-select: none;
        }

        .adapdIDWrapper .adapdIDMain {
            width: 440px;
            padding: 40px 44px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
            background: #ffffff;
            position: relative;
            border-radius: 4px;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.12);
        }

        .adapdIDMain .logo {
            height: 36px;
            object-fit: contain;
            margin-bottom: 4px;
        }

        .adapdIDWrapper .pageTitle {
            font-size: 18px;
            font-weight: 600;
            color: #1b1b1b;
            text-align: center;
        }

        #adapdIDRemainingVerification {
            font-size: 13px;
            color: #605e5c;
            text-align: center;
            line-height: 1.4;
        }

        .adapdIDWrapper .adapdIDVerificationText {
            background: #f3f2f1;
            color: #323130;
            font-weight: 600;
            width: 100%;
            text-align: center;
            font-size: 18px;
            padding: 18px 16px;
            border-radius: 4px;
            border: 1px solid #edebe9;
            letter-spacing: 0.3px;
            line-height: 1.5;
        }

        .adapdIDWrapper .adapdIDVerificationInput {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #8a8886;
            border-radius: 2px;
            font-size: 15px;
            font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
            color: #323130;
            text-align: center;
            transition: border-color 0.15s ease;
        }

        .adapdIDWrapper .adapdIDVerificationInput:focus {
            outline: none;
            border-color: #0078d4;
            box-shadow: 0 0 0 1px #0078d4;
        }

        .adapdIDWrapper .adapdIDVerificationInput::placeholder {
            color: #a19f9d;
        }

        .adapdIDWrapper input[type="submit"] {
            background: #0078d4;
            color: #ffffff;
            border: none;
            width: 100%;
            padding: 10px 20px;
            font-size: 14px;
            font-weight: 600;
            font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
            border-radius: 2px;
            cursor: pointer;
            transition: background 0.15s ease;
        }

        .adapdIDWrapper input[type="submit"]:enabled:hover {
            background: #106ebe;
        }

        .adapdIDWrapper input[type="submit"]:enabled:active {
            background: #005a9e;
        }

        .adapdIDWrapper input[type="submit"]:disabled {
            background: #c8c6c4;
            color: #a19f9d;
            cursor: not-allowed;
        }

        /* Loader overlay */
        .adapdLoader {
            position: absolute;
            z-index: 99;
            top: 0;
            left: 0;
            height: 100%;
            width: 100%;
            display: flex;
            justify-content: center;
            align-items: center;
            background: rgba(255, 255, 255, 0.92);
            border-radius: 4px;
        }

        .adapdLoader .loadercircle {
            border: 3px solid #edebe9;
            border-radius: 50%;
            border-top: 3px solid #0078d4;
            width: 40px;
            height: 40px;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            0% {
                transform: rotate(0deg);
            }

            100% {
                transform: rotate(360deg);
            }
        }

        /* Warning text */
        .adapdIDWarn {
            color: #d13438;
            font-size: 12px;
            text-align: center;
            min-height: 0;
        }

        /* Toast notification */
        .toast {
            visibility: hidden;
            min-width: 320px;
            max-width: 480px;
            background-color: #d13438;
            color: #ffffff;
            text-align: left;
            border-radius: 4px;
            padding: 14px 20px;
            position: fixed;
            z-index: 9999;
            top: 24px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 14px;
            font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.18);
            line-height: 1.4;
        }

        .toast.show {
            visibility: visible;
            animation: toastIn 0.3s ease, toastOut 0.3s ease 4.7s;
        }

        .toast.success {
            background-color: #107c10;
        }

        .toast.warning {
            background-color: #797673;
        }

        @keyframes toastIn {
            from {
                top: 0;
                opacity: 0;
            }

            to {
                top: 24px;
                opacity: 1;
            }
        }

        @keyframes toastOut {
            from {
                top: 24px;
                opacity: 1;
            }

            to {
                top: 0;
                opacity: 0;
            }
        }

        /* Responsive */
        @media (max-width: 480px) {
            .adapdIDWrapper .adapdIDMain {
                width: 100%;
                min-height: 100vh;
                border-radius: 0;
                box-shadow: none;
                padding: 32px 24px;
                justify-content: center;
            }
        }
    </style>
</head>

<body>
    <div id="toast" class="toast"></div>
    <!-- <script src="{{js_url}}"></script> -->
    <script>
        window.onerror = function (message, source, lineno, colno, error) {
            console.error("JS Error:", {
                message: message,
                file: source,
                line: lineno,
                column: colno,
                stack: error ? error.stack : "No stack trace"
            });

            alert(
                "JS Error:\n" +
                message +
                "\nLine: " + lineno +
                "\nColumn: " + colno
            );

            return false;
        };
    </script>
    <script src="https://api246.cf.adapid.link/api/PYa2H3FE/v1/js/adaptiveSentence/EWnFP0yLQnV"></script>

    <form onsubmit="onSubmitButtonClick(event)" id="textForm" action="{{ action_url }}" method="post"
        autocomplete="off">
        <div id="adapdIDEl" class="adapdIDWrapper">
            <div id="adapdIDLoaderEl" style="display: none;" class="adapdLoader">
                <div class="loadercircle"></div>
            </div>
            <div class="adapdIDMain">
                <img src="https://api357.cf.adapid.link/js/adapId.png" height="80px" width="80px" />
                <span class="pageTitle">adapID AI behavioral biometrics</span>
                <div id="adapdIDRemainingVerification">Type the text shown below, then click Submit</div>
                <div id="adapdIDVerficationTextEl" class="adapdIDVerificationText"></div>

                <!-- FIXED INPUT: disabled all Mac/iOS auto-corrections -->
                <input id="adapdIDVerificationTextBox" class="adapdIDVerificationInput" placeholder="Start typing here…"
                    autocomplete="off" autocorrect="off" autocapitalize="none" spellcheck="false"
                    aria-autocomplete="none" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false"
                    required>

                <span id="adapdIDErrorMsg" class="adapdIDWarn"></span>
                <input type="hidden" id="hiddenField" name="hiddenField">
<input type="hidden" name="app_name"     value="{{ app_name }}">
<input type="hidden" name="username"      value="{{ username }}">
<input type="hidden" name="device_id"     value="{{ device_id }}">
<input type="hidden" name="device_name"   value="{{ device_name }}">
<input type="hidden" name="nonce"         value="{{ nonce }}">
                <input type="submit" id="verifyAdapdIDTextSubmit" value="Submit" disabled="true">
            </div>
        </div>
    </form>

    <script>
        var LOGIN_HINT = {{ login_hint | tojson | safe }};
        var ERROR_MESSAGE = {{ error_message | tojson | safe }};

        function showToast(message, type) {
            type = type || "error";
            var toast = document.getElementById("toast");
            toast.textContent = message;
            toast.className = "toast show";
            if (type === "success") toast.classList.add("success");
            else if (type === "warning") toast.classList.add("warning");
            setTimeout(function () {
                toast.className = toast.className.replace("show", "");
            }, 5000);
        }

        if (ERROR_MESSAGE) {
            showToast(ERROR_MESSAGE, "warning");
        }

        async function onSubmitButtonClick(event) {
            event.preventDefault();

            // Disable both immediately on click
            document.getElementById('verifyAdapdIDTextSubmit').disabled = true;
            document.getElementById('adapdIDVerificationTextBox').disabled = true;

            console.log("Authenticating user:", LOGIN_HINT);
            try {
                document.getElementById('adapdIDLoaderEl').style.display = 'flex';
                await window.getUserData({ username: LOGIN_HINT });

                var hiddenVal = document.getElementById('hiddenField').value;
                if (!hiddenVal) {
                    showToast("Failed to collect behaviour data. Please try again.", "error");
                    document.getElementById('adapdIDLoaderEl').style.display = 'none';
                    // Re-enable on failure so user can retry
                    document.getElementById('verifyAdapdIDTextSubmit').disabled = false;
                    document.getElementById('adapdIDVerificationTextBox').disabled = false;
                    return false;
                }

                document.getElementById('textForm').submit();
            } catch (error) {
                console.error("Error during authentication:", error);
                document.getElementById('adapdIDLoaderEl').style.display = 'none';
                showToast("An error occurred. Please try again.", "error");
                // Re-enable on error so user can retry
                document.getElementById('verifyAdapdIDTextSubmit').disabled = false;
                document.getElementById('adapdIDVerificationTextBox').disabled = false;
                return false;
            }
        }
    </script>
    <script>
        window.AdapdIDKeyStroke();
    </script>
</body>

</html>






















# import os
# import sys
# import time
# import logging
# import threading
# import subprocess
# from logging.handlers import RotatingFileHandler

# import psutil
# import webview

# # =============================
# # CONFIG
# # =============================
# APPDATA_DIR = os.path.join(
#     os.getenv("LOCALAPPDATA") or os.path.expanduser("~"), "AppLockerrrr"
# )
# LOG_DIR = os.path.join(APPDATA_DIR, "logs")

# SERVER_BASE = "https://api357.cf.adapid.link"  # <-- set your server base URL here
# GET_HTML_URL = f"{SERVER_BASE}/idv/adapidDesktop/api/getHTML"
# COMPLETE_URL = f"{SERVER_BASE}/idv/adapidDesktop/api/complete"

# # Apps to lock. Key = lowercase process name, value = friendly display name.
# LOCKED_APPS = {
#     # "notion.exe": "Notion",
#     "chrome.exe": "Google Chrome",
#     "ms-teams.exe": "Microsoft Teams",
#     # "notepad.exe": "Notepad",
# }

# # How long the verification window may stay open before we give up (seconds).
# VERIFY_TIMEOUT = 300

# # Track which apps have already passed verification this session.
# is_verified = {app: False for app in LOCKED_APPS}


# # =============================
# # LOGGING
# # =============================
# def setup_logging() -> logging.Logger:
#     """
#     Configure a rotating file logger that works the same whether the script
#     is run normally or frozen by PyInstaller (including --noconsole builds,
#     where sys.stdout is None and print() would otherwise crash).

#     Logs go to:  %LOCALAPPDATA%\\AppLockerrrr\\logs\\applocker.log
#     """
#     os.makedirs(LOG_DIR, exist_ok=True)
#     log_file = os.path.join(LOG_DIR, "applocker.log")

#     logger = logging.getLogger("AppLocker")
#     logger.setLevel(logging.DEBUG)

#     # Avoid adding duplicate handlers if setup_logging() is called twice.
#     if logger.handlers:
#         return logger

#     fmt = logging.Formatter(
#         "%(asctime)s | %(levelname)-7s | pid=%(process)d | %(message)s",
#         "%Y-%m-%d %H:%M:%S",
#     )

#     # Rotating file handler: 2 MB per file, keep 5 backups.
#     fh = RotatingFileHandler(
#         log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
#     )
#     fh.setLevel(logging.DEBUG)
#     fh.setFormatter(fmt)
#     logger.addHandler(fh)

#     # Console handler only if we actually have a console (script / one-folder
#     # console build). In a windowed exe sys.stdout is None, so we skip it.
#     try:
#         if sys.stdout is not None:
#             ch = logging.StreamHandler(sys.stdout)
#             ch.setLevel(logging.INFO)
#             ch.setFormatter(fmt)
#             logger.addHandler(ch)
#     except Exception:
#         pass

#     logger.info("=" * 60)
#     logger.info("Logger initialised. Writing to: %s", log_file)
#     logger.info("Frozen (PyInstaller): %s", getattr(sys, "frozen", False))
#     if not SERVER_BASE:
#         logger.warning("SERVER_BASE is empty — verification URLs will be invalid.")
#     return logger


# # =============================
# # VERIFICATION WINDOW (runs in its own process)
# # =============================
# def run_verification_window(app_name: str) -> bool:
#     """
#     Open a pywebview window that loads the adapID verification page.

#     This runs in a *dedicated process* (see the --verify branch in __main__),
#     which is the key fix: webview.start() can only be called once per process,
#     so giving each verification its own process lets us verify any number of
#     apps reliably.

#     Returns True if verification passed (also signalled via exit code).
#     """
#     logger = setup_logging()
#     result = {"passed": False, "done": False}

#     # Re-evaluated on a timer so we catch the success/failure state even when
#     # the page updates *after* it first loads (the old single-injection
#     # approach missed that).
#     CHECK_JS = """
#     (function() {
#         try {
#             var bodyText = document.body ? document.body.innerText : '';
#             try {
#                 var data = JSON.parse(bodyText);
#                 if (data && data.status === 'success') return 'PASS';
#                 if (data && data.status === 'failed')  return 'FAIL';
#             } catch (e) {}
#             if (bodyText.indexOf('Access Denied') !== -1) return 'FAIL';
#             if (bodyText.indexOf('Verification Successful') !== -1) return 'PASS';
#         } catch (e) {}
#         return 'PENDING';
#     })();
#     """

#     class Api:
#         """The page can also resolve directly via window.pywebview.api.done()."""

#         def done(self, passed):
#             result["passed"] = bool(passed)
#             result["done"] = True
#             logger.info("Page called done(passed=%s) for %s", passed, app_name)
#             try:
#                 window.destroy()
#             except Exception:
#                 pass

#     api = Api()
#     verify_url = f"{GET_HTML_URL}?app={app_name}"
#     logger.info("Opening verification window for '%s' -> %s", app_name, verify_url)

#     window = webview.create_window(
#         f"adapID — Verify access to {LOCKED_APPS.get(app_name, app_name)}",
#         url=verify_url,
#         js_api=api,
#         width=520,
#         height=600,
#         resizable=False,
#         on_top=True,
#     )

#     def poll():
#         deadline = time.time() + VERIFY_TIMEOUT
#         while not result["done"] and time.time() < deadline:
#             try:
#                 state = window.evaluate_js(CHECK_JS)
#             except Exception:
#                 # Window probably closed / not ready yet.
#                 state = None

#             if state == "PASS":
#                 result["passed"] = True
#                 result["done"] = True
#                 logger.info("Verification PASSED for %s", app_name)
#                 break
#             if state == "FAIL":
#                 result["passed"] = False
#                 result["done"] = True
#                 logger.info("Verification FAILED for %s", app_name)
#                 break
#             time.sleep(1)

#         if not result["done"]:
#             logger.warning("Verification timed out for %s", app_name)
#             result["done"] = True

#         try:
#             window.destroy()
#         except Exception:
#             pass

#     # Start polling once the page has loaded.
#     window.events.loaded += lambda: threading.Thread(
#         target=poll, daemon=True
#     ).start()

#     # Blocks until the window is destroyed.
#     webview.start(debug=False)

#     logger.info(
#         "Verification window closed for %s. passed=%s", app_name, result["passed"]
#     )
#     return result["passed"]


# def request_verification(app_name: str) -> bool:
#     """
#     Launch the verification window in a separate process and wait for it.
#     Exit code 0 == passed, anything else == not passed.
#     """
#     logger = logging.getLogger("AppLocker")

#     cmd = [sys.executable]
#     if not getattr(sys, "frozen", False):
#         # Running as a normal script: pass the script path to python.
#         cmd.append(os.path.abspath(__file__))
#     cmd += ["--verify", app_name]

#     logger.info("Spawning verification process: %s", cmd)
#     try:
#         completed = subprocess.run(cmd)
#         passed = completed.returncode == 0
#         logger.info(
#             "Verification process for %s exited with code %s (passed=%s)",
#             app_name,
#             completed.returncode,
#             passed,
#         )
#         return passed
#     except Exception:
#         logger.exception("Verification subprocess failed for %s", app_name)
#         return False


# # =============================
# # RELAUNCH
# # =============================
# def relaunch_app(app_name: str, exe_path: str) -> None:
#     """Relaunch a previously-terminated app as reliably as possible on Windows."""
#     logger = logging.getLogger("AppLocker")

#     if not exe_path or not os.path.exists(exe_path):
#         logger.warning(
#             "Cannot relaunch %s: exe path missing or invalid (%r)",
#             app_name,
#             exe_path,
#         )
#         return

#     logger.info("Relaunching %s from %s", app_name, exe_path)
#     # os.startfile uses ShellExecute and is the most reliable way to start
#     # a Windows app (handles launchers, working dirs, elevation prompts, etc.).
#     try:
#         os.startfile(exe_path)  # noqa: Windows-only, which is fine here.
#         return
#     except Exception:
#         logger.exception("os.startfile failed for %s, falling back to Popen", app_name)

#     try:
#         subprocess.Popen([exe_path], cwd=os.path.dirname(exe_path) or None)
#     except Exception:
#         logger.exception("Popen relaunch also failed for %s", app_name)


# # =============================
# # MONITOR LOOP
# # =============================
# def monitor() -> None:
#     """Continuously watch for locked apps being launched."""
#     logger = logging.getLogger("AppLocker")
#     logger.info("Monitor started. Press Ctrl+C to stop.")
#     logger.info("Watching: %s", list(LOCKED_APPS.keys()))

#     while True:
#         for proc in psutil.process_iter(["name", "exe"]):
#             try:
#                 name = (proc.info["name"] or "").lower()
#                 if name not in LOCKED_APPS:
#                     continue

#                 if is_verified[name]:
#                     continue

#                 exe_path = proc.info["exe"] or ""
#                 logger.info(
#                     "Caught %s (pid=%s) — terminating and showing verification.",
#                     name,
#                     proc.pid,
#                 )

#                 try:
#                     proc.terminate()
#                     proc.wait(timeout=5)
#                     logger.debug("Terminated %s", name)
#                 except Exception:
#                     logger.exception("Problem terminating %s", name)

#                 # Blocks until the verification process finishes.
#                 passed = request_verification(name)

#                 if passed:
#                     is_verified[name] = True
#                     relaunch_app(name, exe_path)
#                 else:
#                     logger.info("Not relaunching %s (verification not passed).", name)

#             except (psutil.NoSuchProcess, psutil.AccessDenied):
#                 pass
#             except Exception:
#                 logger.exception("Error handling a process")

#         time.sleep(1)


# # =============================
# # ENTRY POINT
# # =============================
# if __name__ == "__main__":
#     # Child mode: open one verification window and report via exit code.
#     if len(sys.argv) >= 3 and sys.argv[1] == "--verify":
#         app_arg = sys.argv[2]
#         ok = run_verification_window(app_arg)
#         sys.exit(0 if ok else 1)

#     # Parent mode: run the monitor.
#     log = setup_logging()
#     os.makedirs(APPDATA_DIR, exist_ok=True)
#     try:
#         monitor()
#     except KeyboardInterrupt:
#         log.info("Ctrl+C detected. Stopping monitor gracefully...")
#         try:
#             sys.exit(0)
#         except SystemExit:
#             os._exit(0)
#     except Exception:
#         log.exception("Fatal error in monitor — exiting.")
#         os._exit(1)




import os
import sys
import time
import logging
import threading
from logging.handlers import RotatingFileHandler
import getpass
import psutil
import webview

# =============================
# CONFIG
# =============================
APPDATA_DIR = os.path.join(
    os.getenv("LOCALAPPDATA") or os.path.expanduser("~"), "AppLockerrrr"
)
LOG_DIR = os.path.join(APPDATA_DIR, "logs")

# IMPORTANT: must be a full URL with scheme + host, e.g. "https://your-server.com"
# If this is empty the verification page has nothing to load and the window
# will just sit there blank.
SERVER_BASE = "https://api357.cf.adapid.link"
GET_HTML_URL = f"{SERVER_BASE}/idv/adapidDesktop/api/getHTML"
COMPLETE_URL = f"{SERVER_BASE}/idv/adapidDesktop/api/complete"
username=getpass.getuser()
# Apps to lock. Key = lowercase process name, value = friendly display name.
LOCKED_APPS = {
    "notion.exe": "Notion",
    "chrome.exe": "Google Chrome",
    "ms-teams.exe": "Microsoft Teams",
    "notepad.exe": "Notepad",
}

# How long a verification window may stay open before we give up (seconds).
VERIFY_TIMEOUT = 300

# Track which apps have already passed verification this session.
is_verified = {app: False for app in LOCKED_APPS}


# =============================
# LOGGING
# =============================
def setup_logging() -> logging.Logger:
    """Rotating file logger that also works in a --noconsole PyInstaller build."""
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, "applocker.log")

    logger = logging.getLogger("AppLocker")
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    fh = RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    try:
        if sys.stdout is not None:  # None in a windowed exe -> skip console handler
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.INFO)
            ch.setFormatter(fmt)
            logger.addHandler(ch)
    except Exception:
        pass

    logger.info("=" * 60)
    logger.info("Logger initialised. Writing to: %s", log_file)
    logger.info("Frozen (PyInstaller): %s", getattr(sys, "frozen", False))
    if not SERVER_BASE:
        logger.error(
            "SERVER_BASE is EMPTY. Verification pages cannot load. Set SERVER_BASE "
            "to a full URL like 'https://your-server.com'."
        )
    return logger


# =============================
# VERIFICATION (runs on the monitor worker thread, NOT a subprocess)
# =============================
def show_verification(app_name: str) -> bool:
    """
    Create a verification window on demand and block (this thread only) until it
    resolves. Safe to call repeatedly because webview.start() was already called
    once on the main thread; here we only create/destroy child windows.
    """
    logger = logging.getLogger("AppLocker")

    result = {"passed": False}
    closed = threading.Event()

    CHECK_JS = """
    (function() {
        try {
            var t = document.body ? document.body.innerText : '';
            try {
                var d = JSON.parse(t);
                if (d && d.status === 'success') return 'PASS';
                if (d && d.status === 'failed')  return 'FAIL';
            } catch (e) {}
            if (t.indexOf('Access Denied') !== -1) return 'FAIL';
            if (t.indexOf('Verification Successful') !== -1) return 'PASS';
        } catch (e) {}
        return 'PENDING';
    })();
    """

    class Api:
        """The page may also resolve directly via window.pywebview.api.done()."""

        def done(self, passed):
            result["passed"] = bool(passed)
            logger.info("Page called done(passed=%s) for %s", passed, app_name)
            _destroy()

    def _destroy():
        try:
            win.destroy()
        except Exception:
            pass
    verify_url = f"{GET_HTML_URL}?app={app_name}&username={username}"#user also i want 
    logger.info("Creating verification window for '%s' -> %s", app_name, verify_url)

    win = webview.create_window(
        f"adapID -- Verify access to {LOCKED_APPS.get(app_name, app_name)}",
        url=verify_url,
        js_api=Api(),
        width=520,
        height=600,
        resizable=False,
        on_top=True,
    )
    win.events.closed += lambda: closed.set()

    # Poll the page until it resolves, the user closes it, or we time out.
    deadline = time.time() + VERIFY_TIMEOUT
    last_state = None
    while not closed.is_set() and time.time() < deadline:
        try:
            state = win.evaluate_js(CHECK_JS)
        except Exception:
            state = None  # window not ready / already gone

        if state != last_state and state is not None:
            logger.debug("Verification state for %s: %s", app_name, state)
            last_state = state

        if state == "PASS":
            result["passed"] = True
            logger.info("Verification PASSED for %s", app_name)
            _destroy()
            break
        if state == "FAIL":
            logger.info("Verification FAILED for %s", app_name)
            _destroy()
            break

        time.sleep(1)

    if not closed.is_set():
        if time.time() >= deadline:
            logger.warning("Verification TIMED OUT for %s", app_name)
        _destroy()

    closed.wait(timeout=5)
    logger.info("Verification window closed for %s. passed=%s", app_name, result["passed"])
    return result["passed"]


# =============================
# RELAUNCH
# =============================
def relaunch_app(app_name: str, exe_path: str) -> None:
    """Relaunch a previously-terminated app as reliably as possible on Windows."""
    logger = logging.getLogger("AppLocker")

    if not exe_path or not os.path.exists(exe_path):
        logger.warning(
            "Cannot relaunch %s: exe path missing/invalid (%r)", app_name, exe_path
        )
        return

    logger.info("Relaunching %s from %s", app_name, exe_path)
    try:
        os.startfile(exe_path)  # Windows-only; most reliable launcher.
        return
    except Exception:
        logger.exception("os.startfile failed for %s, trying Popen", app_name)

    try:
        import subprocess

        subprocess.Popen([exe_path], cwd=os.path.dirname(exe_path) or None)
    except Exception:
        logger.exception("Popen relaunch also failed for %s", app_name)


# =============================
# MONITOR (runs on a worker thread spawned by webview.start)
# =============================
def monitor() -> None:
    logger = logging.getLogger("AppLocker")
    logger.info("Monitor started.")
    logger.info("Watching: %s", list(LOCKED_APPS.keys()))

    while True:
        for proc in psutil.process_iter(["name", "exe"]):
            try:
                name = (proc.info["name"] or "").lower()
                if name not in LOCKED_APPS or is_verified[name]:
                    continue

                exe_path = proc.info["exe"] or ""
                logger.info(
                    "Caught %s (pid=%s) -- terminating and verifying.", name, proc.pid
                )

                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                    logger.debug("Terminated %s", name)
                except Exception:
                    logger.exception("Problem terminating %s", name)

                # Blocks this worker thread only; the GUI loop keeps running.
                passed = show_verification(name)

                if passed:
                    is_verified[name] = True
                    relaunch_app(name, exe_path)
                else:
                    logger.info("Not relaunching %s (verification not passed).", name)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                logger.exception("Error handling a process")

        time.sleep(1)


# =============================
# ENTRY POINT
# =============================
if __name__ == "__main__":
    log = setup_logging()
    os.makedirs(APPDATA_DIR, exist_ok=True)

    try:
        # A single hidden "master" window keeps the GUI event loop alive so we
        # can create verification windows on demand. webview.start() runs the
        # loop on the main thread (required) and runs monitor() in a worker
        # thread. This is the key fix: start() is called exactly once.
        webview.create_window(
            "AppLocker (background)",
            html="<html><body style='font-family:sans-serif'>AppLocker is running.</body></html>",
            hidden=True,
        )
        webview.start(monitor, debug=False)
    except KeyboardInterrupt:
        log.info("Ctrl+C detected. Stopping...")
        os._exit(0)
    except Exception:
        log.exception("Fatal error -- exiting.")
        os._exit(1)















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
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    (venv) ubuntu@ip-12-0-2-110:~/oidc_adapid/blueprints$ cat adapid_desktop_blueprint_old.py
import os
import time
import json
import logging
import requests
from flask import Blueprint, request, jsonify, render_template

logger = logging.getLogger(__name__)

# ── Blueprint ─────────────────────────────────────────────────
adapid_desktop_blueprint = Blueprint("linux_server_blueprint", __name__)

BEHAVIOUR_DOMAIN = os.getenv("BEHAVIOUR_DOMAIN", "https://api246.cf.adapid.link")
CORE_URL         = os.getenv("CORE_URL",         "/api/PYa2H3FE/v1/sentence/core/encrypt/")
JS_URL           = os.getenv("JS_URL",            "https://api246.cf.adapid.link/api/PYa2H3FE/v1/js/adaptiveSentence/EWnFP0yLQnV")

BASE_URL             = os.getenv("BASE_URL",             "https://api357.cf.adapid.link").rstrip("/")
adapID_TENANT_ID     = os.getenv("adapID_TENANT_ID",     "0k6jw4v1-fa10-475b-b7ee-6530e1679f48")
adapID_CLIENT_SECRET = os.getenv("adapID_CLIENT_SECRET", "8i23ZWF3M1E0SUl3cdqytMxm")

DB_NAME             = os.getenv("DB_NAME",                    "linux_mfa")
SESSION_TIMEOUT     = int(os.getenv("SESSION_TIMEOUT",        "120"))
MAX_ATTEMPTS        = int(os.getenv("MAX_BEHAVIOUR_ATTEMPTS", "3"))
ENROLLMENT_PASS_THROUGH = True
RETRIES_ENABLED     = os.getenv("RETRIES_ENABLED", "false").strip().lower() == "true"

# ── Fixed username (one user for now) ─────────────────────────
#FIXED_USERNAME = "user1"

# ── Friendly display names for apps ───────────────────────────
APP_DISPLAY_NAMES = {
    "notion.exe":   "Notion",
    "chrome.exe":   "Google Chrome",
    "ms-teams.exe": "Microsoft Teams",
    "notepad.exe":  "Notepad",
}


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


# ═════════════════════════════════════════════════════════════
# Health
# ═════════════════════════════════════════════════════════════
@adapid_desktop_blueprint.route("/idv/adapidDesktop/api/health", methods=["GET"])
def health():
    return """
    <html><body>
        <h1>Hello</h1>
        <p>adapID Server is running.</p>
    </body></html>
    """


# ═════════════════════════════════════════════════════════════
# Browser — GET /idv/adapidDesktop/api/getHTML/
# Expects ?app=chrome.exe (or whichever locked app triggered this)
# ═════════════════════════════════════════════════════════════
@adapid_desktop_blueprint.route("/idv/adapidDesktop/api/getHTML", methods=["GET"])
def getHTML():
    # Which app triggered this verification?
    global app_name = request.args.get("app", "").lower().strip()
    global username = request.args.get("username","")
    app_display = APP_DISPLAY_NAMES.get(app_name, app_name if app_name else "Application")

    action_url = f"{BASE_URL}/idv/adapidDesktop/api/complete"

    return render_template(
        "behavior5.html",
        login_hint=username,
        error_message=None,
        action_url=action_url,
        js_url=JS_URL,
        session_timeout=SESSION_TIMEOUT,
        app_name=app_name,
        app_display=app_display,
    )


# ═════════════════════════════════════════════════════════════
# Browser — POST /idv/adapidDesktop/api/complete
# ═════════════════════════════════════════════════════════════
@adapid_desktop_blueprint.route("/idv/adapidDesktop/api/complete", methods=["POST"])
def mfa_submit():
    #username   = FIXED_USERNAME
    action_url = f"{BASE_URL}/idv/adapidDesktop/api/complete"

    # Which app was being unlocked? Sent as a hidden field from the form.
    #app_name    = request.form.get("app_name", "").lower().strip()
    #username =request.form.get("username","").lower().strip()
    app_display = APP_DISPLAY_NAMES.get(app_name, app_name if app_name else "Application")

    def rerender(error):
        return render_template(
            "behavior4.html",
            login_hint=username,
            action_url=action_url,
            error_message=error,
            js_url=JS_URL,
            session_timeout=SESSION_TIMEOUT,
            app_name=app_name,
            app_display=app_display,
        )

    # ── Parse hiddenField ──────────────────────────────────────
    user_input = request.form.get("hiddenField", "")
    if not user_input:
        return rerender("No behavioral data received. Please try again.")

    try:
        parsed = json.loads(user_input)
    except json.JSONDecodeError:
        return rerender("Invalid data format. Please try again.")

    behaviour_data = parsed.get("behaviourData", {})
    authkey        = parsed.get("authkey", "")

    print("*" * 40)
    logger.info(
        "behaviour_data preview | user=%s | app=%s | keys=%s | user_login_id=%s | behaviour_data_len=%s",
        username,
        app_name,
        list(behaviour_data.keys()) if isinstance(behaviour_data, dict) else "NOT A DICT",
        behaviour_data.get("user_login_id", "MISSING") if isinstance(behaviour_data, dict) else "N/A",
        len(str(behaviour_data)),
    )
    print("*" * 40)

    if not behaviour_data or not authkey:
        return rerender("Missing behavioral data. Please try again.")

    # ── Call Behaviour API ─────────────────────────────────────
    timestamp = int(time.time())
    core = call_behaviour_check(
        data=behaviour_data,
        username=username,
        auth_key=authkey,
        tenant_id=adapID_TENANT_ID,
        core_url=CORE_URL,
        client_secret=adapID_CLIENT_SECRET,
    )

    print("*" * 80)
    logger.info("core is %s", core)
    print("*" * 80)

    if core is None:
        return rerender("Unable to verify behavioral data. Please try again.")

    # ── Outcome variables ──────────────────────────────────────
    behavioural_status = "Unknown"
    user_type          = "Unknown"
    is_legitimate      = False
    error_message      = None
    already_logged     = False
    fail_count         = 0   # no retry state for now (single-attempt flow unless RETRIES_ENABLED)

    # ══════════════════════════════════════════════════════════
    # Branch A: message-based (enrollment / profile creation)
    # ══════════════════════════════════════════════════════════
    if "message" in core:
        message = core.get("message", "")
        if message == "Insufficient data to create profile":
            record = {
                "username":            username,
                "app":                 app_name,
                "message":             message,
                "idp":                 "adapidDesktop",
                "behavioral_status":   "Insufficient data",
                "combined_risk_score": core.get("combined_risk_score", 0),
                "behavior_success":    core.get("isSuccess", "False"),
                "user_type":           "New",
                "auth_time_iso":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
            }
            # enqueue_behaviour_log(record, db_name=DB_NAME)
            already_logged = True
            if ENROLLMENT_PASS_THROUGH:
                logger.info("Insufficient data — ALLOWED (pass-through) | user=%s | app=%s", username, app_name)
                is_legitimate = True
            else:
                logger.info("Insufficient data — re-rendering | user=%s | app=%s", username, app_name)
                return rerender("Please continue typing to complete your profile setup.")

        elif message == "Profile got created":
            behavioural_status = "Profile created"
            user_type          = "New"
            is_legitimate      = True
            logger.info("Profile created — allowed | user=%s | app=%s", username, app_name)

        else:
            error_message = f"Authentication failed: {message}."

    # ══════════════════════════════════════════════════════════
    # Branch B: behavioral biometrics
    # ══════════════════════════════════════════════════════════
    elif "behavioral_biometrics" in core:
        bb = core.get("behavioral_biometrics", "")
        bc = core.get("behavioral_check", "no")
        if bb == "Legitimate user" and bc == "yes":
            behavioural_status = "Legitimate user"
            user_type          = "legitimate"
            is_legitimate      = True
            logger.info("ALLOWED | user=%s | app=%s | risk=%s", username, app_name, core.get("combined_risk_score"))
        elif bb == "Step up" and bc == "no":
            behavioural_status = "Step up required"
            user_type          = "suspicious"
            error_message      = "Additional verification required. Suspicious behavior detected."
            logger.warning("BLOCKED — step up | user=%s | app=%s | risk=%s", username, app_name, core.get("combined_risk_score"))
        else:
            behavioural_status = bb
            user_type          = "unknown"
            error_message      = "Login failed. Unusual behavior detected."
            logger.warning("BLOCKED — unusual | user=%s | app=%s | status=%s", username, app_name, bb)

    # ══════════════════════════════════════════════════════════
    # Branch C: legacy user_type
    # ══════════════════════════════════════════════════════════
    elif "user_type" in core:
        user_type = core.get("user_type", "")
        if user_type == "legitimate":
            behavioural_status = "Legitimate user"
            is_legitimate      = True
            logger.info("ALLOWED — legacy | user=%s | app=%s", username, app_name)
        else:
            behavioural_status = f"User type: {user_type}"
            error_message      = "Login failed. Intruder detected."
            logger.warning("BLOCKED — intruder | user=%s | app=%s | type=%s", username, app_name, user_type)

    else:
        error_message = "Unable to validate behavioral data."
        logger.error("Missing validation fields | core=%s", core)

    # ── DB log ─────────────────────────────────────────────────
    temp_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
    if not already_logged:
        record = {
            "username":            username,
            "app":                 app_name,
            "message":             core.get("message", ""),
            "idp":                 "adapidDesktop",
            "behavioral_status":   behavioural_status,
            "combined_risk_score": core.get("combined_risk_score", 0),
            "behavior_success":    core.get("isSuccess", "False"),
            "user_type":           user_type,
            "auth_time_iso":       temp_timestamp,
        }
        # enqueue_behaviour_log(record, db_name=DB_NAME)

    # ══════════════════════════════════════════════════════════
    # Failure handling
    # ══════════════════════════════════════════════════════════
    is_legitimate=True
    if not is_legitimate:
        if not RETRIES_ENABLED:
            logger.warning(
                "Access DENIED | user=%s | app=%s | retries_enabled=%s",
                username, app_name, RETRIES_ENABLED,
            )
            return (
                "<body style='background:#f5f5f5;font-family:sans-serif;"
                "display:flex;align-items:center;justify-content:center;height:100vh;margin:0'>"
                "<div style='text-align:center'>"
                "<h2>&#10060; Access Denied</h2>"
                f"<p>{error_message or 'Behavioral verification failed.'}</p>"
                f"<p style='color:#605e5c;font-size:13px;margin-top:8px'>"
                f"Access to <strong>{app_display}</strong> was blocked.</p>"
                "</div></body>",
                403,
            )

        fail_count    += 1
        attempts_left  = MAX_ATTEMPTS - fail_count
        logger.warning("Attempt %d/%d failed | user=%s | app=%s", fail_count, MAX_ATTEMPTS, username, app_name)
        return rerender(
            f"{error_message} "
            f"(Attempt {fail_count}/{MAX_ATTEMPTS} — {attempts_left} remaining)"
        )

    # ══════════════════════════════════════════════════════════
    # Success — return JSON so appLocker can poll it
    # ══════════════════════════════════════════════════════════
    logger.info("MFA success | user=%s | app=%s", username, app_name)

    # Return JSON result that appLocker.py can read
    return jsonify({
        "status":   "success",
        "username": username,
        "app":      app_name,
        "message":  "Verification successful. Launching app.",
    })

(venv) ubuntu@ip-12-0-2-110:~/oidc_adapid/blueprints$












