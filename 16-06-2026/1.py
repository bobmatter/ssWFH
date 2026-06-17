"""
Linux SSH Behavioral Biometrics MFA Server
Flow: PAM → POST /idv/linser/api/create_session
      → GET  /idv/linser/api/mfa/<token>   (browser)
      → POST /idv/linser/api/complete/<token>
      → PAM polls /idv/linser/api/status/<token>
"""

import os
import time
import json
import secrets
import logging
import requests
import json as _json
from flask import Blueprint, request, jsonify, render_template

logger = logging.getLogger(__name__)

# ── Blueprint ─────────────────────────────────────────────────
linux_server_blueprint = Blueprint("linux_server_blueprint", __name__)


BEHAVIOUR_DOMAIN = os.getenv("BEHAVIOUR_DOMAIN", "https://api246.cf.adapid.link")
CORE_URL         = os.getenv("CORE_URL",         "/api/PYa2H3FE/v1/sentence/core/encrypt/")
JS_URL           = os.getenv("JS_URL",           "https://api246.cf.adapid.link/api/PYa2H3FE/v1/js/adaptiveSentence/EWnFP0yLQnV")

# ── Config ────────────────────────────────────────────────────
BASE_URL                = os.getenv("BASE_URL",                  "https://api357.cf.adapid.link").rstrip("/")
#BEHAVIOUR_DOMAIN        = os.getenv("BEHAVIOUR_DOMAIN",          "https://api246.cf.adapid.link")
ADAPID_TENANT_ID        = os.getenv("ADAPID_TENANT_ID",          "0k6jw4v1-fa10-475b-b7ee-6530e1679f48")
ADAPID_CLIENT_SECRET    = os.getenv("ADAPID_CLIENT_SECRET",      "8i23ZWF3M1E0SUl3cdqytMxm")
#CORE_URL = os.getenv("CORE_URL", "/api/PYa2H3FE/v1/sentence/core/encrypt/")
#JS_URL   = os.getenv("JS_URL",   "/api/PYa2H3FE/v1/js/adaptiveSentence/EWnFP0yLQnV")
# CORE_URL                = os.getenv("CORE_URL",                  "https://api246.cf.adapid.link/api/PYa2H3FE/v1/sentence/core/encrypt/")
# JS_URL                  = os.getenv("JS_URL",                    "https://api246.cf.adapid.link/api/PYa2H3FE/v1/js/adaptiveSentence/EWnFP0yLQnV")
DB_NAME                 = os.getenv("DB_NAME",                   "linux_mfa")
SESSION_TIMEOUT         = int(os.getenv("SESSION_TIMEOUT",       "120"))
MAX_ATTEMPTS            = int(os.getenv("MAX_BEHAVIOUR_ATTEMPTS","3"))
#ENROLLMENT_PASS_THROUGH = os.getenv("ENROLLMENT_PASS_THROUGH",  "true").strip().lower() == "true"
ENROLLMENT_PASS_THROUGH=True
RETRIES_ENABLED         = os.getenv("RETRIES_ENABLED",           "false").strip().lower() == "true"

# ── In-memory session store ───────────────────────────────────
SESSIONS: dict = {}


def _clean_sessions():
    now  = time.time()
    dead = [t for t, s in SESSIONS.items() if now - s["created_at"] > SESSION_TIMEOUT + 60]
    for t in dead:
        del SESSIONS[t]


# def call_behaviour_check(data, username, auth_key, tenant_id, core_url, client_secret):
#     if not BEHAVIOUR_DOMAIN or not core_url:
#         logger.error("Behaviour domain or core_url not configured")
#         return None

#     url = f"{BEHAVIOUR_DOMAIN}{core_url}"
#     try:
#         payload = {**data, "tenant_id": tenant_id}
#         headers = {
#             "Content-Type": "application/json",
#             "X-Secret-Key": client_secret,
#             "Auth-Key": auth_key,
#         }
#         resp = requests.post(url, json=payload, headers=headers, timeout=30)
#         if resp.status_code != 200:
#             logger.error(
#                 "Behaviour API returned %d | tenant=%s | body=%s",
#                 resp.status_code, tenant_id, resp.text[:500],
#             )
#             return None
#         return resp.json()
#     except Exception as e:
#         logger.error("Behaviour API failed | tenant=%s | error=%s", tenant_id, e)
#         return None



def call_behaviour_check(data, username, auth_key, tenant_id, core_url, client_secret):

    if not BEHAVIOUR_DOMAIN or not core_url:
        logger.error("Behaviour domain or core_url not configured")
        return None

    url = f"{BEHAVIOUR_DOMAIN}{core_url}"
    try:
        payload = {**data, "tenant_id": tenant_id}
        logger.info( "Full payload to behaviour API | %s",_json.dumps(payload, indent=2)[:2000])

        headers = {
            "Content-Type": "application/json",
            "X-Secret-Key": client_secret,
            "Auth-Key": auth_key,
        }

        logger.info("Sending to behaviour API | user=%s | tenant=%s | url=%s | data_keys=%s",username, ADAPID_TENANT_ID, CORE_URL, list(data.keys()))

        resp = requests.post(url, json=payload, headers=headers, timeout=30)

        logger.info("Behaviour API response | status=%s | body=%s",
            resp.status_code,
             resp.text[:1000]
               )


        if resp.status_code == 500:
            body = resp.json()
            # API couldn't extract features — treat as insufficient data, not a crash
            if "Failed to get the Feature Vector" in body.get("Error", ""):
                logger.warning(
                    "Feature vector extraction failed | tenant=%s | treating as insufficient data",
                    tenant_id,
                )
                return {"message": "Insufficient data to create profile"}  # ← synthetic response
            logger.error(
                "Behaviour API returned 500 | tenant=%s | body=%s",
                tenant_id, resp.text[:500],
            )
            return None

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

@linux_server_blueprint.route("/idv/linser/api/healtz", methods=["GET"])
def healtz():
    return """
    <html><body>
        <h1>Hello</h1>
        <p>Linux MFA Server is running.</p>
    </body></html>
    """

@linux_server_blueprint.route("/idv/linser/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "sessions": len(SESSIONS), "ts": int(time.time())})


# ═════════════════════════════════════════════════════════════
# PAM API — POST /idv/linser/api/create_session
# ═════════════════════════════════════════════════════════════

@linux_server_blueprint.route("/idv/linser/api/create_session", methods=["POST"])
def create_session():
    """PAM calls this first. Returns {token, mfa_url}."""
    _clean_sessions()
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "username required"}), 400

    token = secrets.token_urlsafe(20)
    SESSIONS[token] = {
        "username":   username,
        "status":     "pending",   # pending | success | failed
        "fail_count": 0,
        "form_data":  None,
        "created_at": time.time(),
    }

    mfa_url = f"{BASE_URL}/idv/linser/api/mfa/{token}"
    return jsonify({"token": token, "mfa_url": mfa_url})


# ═════════════════════════════════════════════════════════════
# PAM API — GET /idv/linser/api/status/<token>
# ═════════════════════════════════════════════════════════════

@linux_server_blueprint.route("/idv/linser/api/status/<token>", methods=["GET"])
def status(token):
    s = SESSIONS.get(token)
    if not s:
        return jsonify({"status": "expired"}), 404
    if time.time() - s["created_at"] > SESSION_TIMEOUT:
        del SESSIONS[token]
        return jsonify({"status": "expired"}), 404
    return jsonify({"status": s["status"]})


# ═════════════════════════════════════════════════════════════
# Browser — GET /idv/linser/api/mfa/<token>
# ═════════════════════════════════════════════════════════════

@linux_server_blueprint.route("/idv/linser/api/mfa/<token>", methods=["GET"])
def mfa_page(token):
    s = SESSIONS.get(token)
    if not s or time.time() - s["created_at"] > SESSION_TIMEOUT:
        return (
            "<body style='background:#f5f5f5;font-family:sans-serif;"
            "display:flex;align-items:center;justify-content:center;height:100vh;margin:0'>"
            "<div style='text-align:center'><h2>⏰ Session expired or invalid.</h2>"
            "<p>Please SSH again to get a new link.</p></div></body>",
            404,
        )
    if s["status"] != "pending":
        msg = "✅ Already verified." if s["status"] == "success" else "❌ Session closed."
        return (
            f"<body style='background:#f5f5f5;font-family:sans-serif;"
            f"display:flex;align-items:center;justify-content:center;height:100vh;margin:0'>"
            f"<h2>{msg}</h2></body>",
            400,
        )

    action_url = f"{BASE_URL}/idv/linser/api/complete/{token}"
    return render_template(
        "behavior3.html",
        token=token,
        login_hint=s["username"],
        error_message=None,
        action_url=action_url,
        js_url=JS_URL,
        session_timeout=SESSION_TIMEOUT,
    )


# ═════════════════════════════════════════════════════════════
# Browser — POST /idv/linser/api/complete/<token>
# ═════════════════════════════════════════════════════════════

@linux_server_blueprint.route("/idv/linser/api/complete/<token>", methods=["POST"])
def mfa_submit(token):
    txn = SESSIONS.get(token)
    if not txn:
        return jsonify({"success": False, "error": "Session expired. Please SSH again."}), 404
    if time.time() - txn["created_at"] > SESSION_TIMEOUT:
        del SESSIONS[token]
        return jsonify({"success": False, "error": "Session expired. Please SSH again."}), 404
    if txn["status"] != "pending":
        return jsonify({"success": False, "error": "Already submitted."}), 400

    username   = txn["username"]
    action_url = f"{BASE_URL}/idv/linser/api/complete/{token}"

    # ── Parse hiddenField ──────────────────────────────────────
    user_input = request.form.get("hiddenField", "")
    if not user_input:
        return render_template(
            "behavior3.html",
            token=token,
            login_hint=username,
            action_url=action_url,
            error_message="No behavioral data received. Please try again.",
            js_url=JS_URL,
            session_timeout=SESSION_TIMEOUT,
        )

    try:
        parsed = json.loads(user_input)
    except json.JSONDecodeError:
        return render_template(
            "behavior3.html",
            token=token,
            login_hint=username,
            action_url=action_url,
            error_message="Invalid data format. Please try again.",
            js_url=JS_URL,
            session_timeout=SESSION_TIMEOUT,
        )

    behaviour_data = parsed.get("behaviourData", {})
    authkey        = parsed.get("authkey", "")


    print("*" * 40)
    logger.info(
    "behaviour_data preview | user=%s | keys=%s | user_login_id=%s | behaviour_data_len=%s",
    username,
    list(behaviour_data.keys()) if isinstance(behaviour_data, dict) else "NOT A DICT",
    behaviour_data.get("user_login_id", "MISSING") if isinstance(behaviour_data, dict) else "N/A",
    len(str(behaviour_data)),)
    print("*" * 40)



    if not behaviour_data or not authkey:
        return render_template(
            "behavior3.html",
            token=token,
            login_hint=username,
            action_url=action_url,
            error_message="Missing behavioral data. Please try again.",
            js_url=JS_URL,
            session_timeout=SESSION_TIMEOUT,
        )

    # ── Call Behaviour API ─────────────────────────────────────
    timestamp = int(time.time())
    core = call_behaviour_check(
        data=behaviour_data,
        username=username,
        #username="saicharan",
        auth_key=authkey,
        tenant_id=ADAPID_TENANT_ID,
        core_url=CORE_URL,
        client_secret=ADAPID_CLIENT_SECRET,
    )
    print("*"*80)
    logger.info("core is %s", core)
    #print(core)
    print("*"*80)
    if core is None:
        return render_template(
            "behavior3.html",
            token=token,
            login_hint=username,
            action_url=action_url,
            error_message="Unable to verify behavioral data. Please try again.",
            js_url=JS_URL,
            session_timeout=SESSION_TIMEOUT,
        )

    # ── Outcome variables ──────────────────────────────────────
    behavioural_status = "Unknown"
    user_type          = "Unknown"
    is_legitimate      = False
    error_message      = None
    already_logged     = False

    # ══════════════════════════════════════════════════════════
    # Branch A: message-based (enrollment / profile creation)
    # ══════════════════════════════════════════════════════════
    if "message" in core:
        message = core.get("message", "")

        if message == "Insufficient data to create profile":
            record = {
                "username":            username,
                "message":             message,
                "idp":                 "linux_ssh",
                "behavioral_status":   "Insufficient data",
                "combined_risk_score": core.get("combined_risk_score", 0),
                "behavior_success":    core.get("isSuccess", "False"),
                "user_type":           "New",
                "auth_time_iso":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
            }
            # enqueue_behaviour_log(record, db_name=DB_NAME)  # wire up when ready
            already_logged = True

            if ENROLLMENT_PASS_THROUGH:
                logger.info("Insufficient data — ALLOWED (pass-through) | user=%s", username)
                is_legitimate = True
            else:
                logger.info("Insufficient data — re-rendering | user=%s", username)
                return render_template(
                    "behavior3.html",
                    token=token,
                    login_hint=username,
                    action_url=action_url,
                    error_message="Please continue typing to complete your profile setup.",
                    js_url=JS_URL,
                    session_timeout=SESSION_TIMEOUT,
                )

        elif message == "Profile got created":
            behavioural_status = "Profile created"
            user_type          = "New"
            is_legitimate      = True
            logger.info("Profile created — allowed | user=%s", username)

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
            logger.info("ALLOWED | user=%s | risk=%s", username, core.get("combined_risk_score"))

        elif bb == "Step up" and bc == "no":
            behavioural_status = "Step up required"
            user_type          = "suspicious"
            error_message      = "Additional verification required. Suspicious behavior detected."
            logger.warning("BLOCKED — step up | user=%s | risk=%s", username, core.get("combined_risk_score"))

        else:
            behavioural_status = bb
            user_type          = "unknown"
            error_message      = "Login failed. Unusual behavior detected."
            logger.warning("BLOCKED — unusual | user=%s | status=%s", username, bb)

    # ══════════════════════════════════════════════════════════
    # Branch C: legacy user_type
    # ══════════════════════════════════════════════════════════
    elif "user_type" in core:
        user_type = core.get("user_type", "")
        if user_type == "legitimate":
            behavioural_status = "Legitimate user"
            is_legitimate      = True
            logger.info("ALLOWED — legacy | user=%s", username)
        else:
            behavioural_status = f"User type: {user_type}"
            error_message      = "Login failed. Intruder detected."
            logger.warning("BLOCKED — intruder | user=%s | type=%s", username, user_type)

    else:
        error_message = "Unable to validate behavioral data."
        logger.error("Missing validation fields | core=%s", core)

    # ── DB log ─────────────────────────────────────────────────
    temp_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
    if not already_logged:
        record = {
            "username":            username,
            "message":             core.get("message", ""),
            "idp":                 "linux_ssh",
            "behavioral_status":   behavioural_status,
            "combined_risk_score": core.get("combined_risk_score", 0),
            "behavior_success":    core.get("isSuccess", "False"),
            "user_type":           user_type,
            "auth_time_iso":       temp_timestamp,
        }
        # enqueue_behaviour_log(record, db_name=DB_NAME)  # wire up when ready

    # ══════════════════════════════════════════════════════════
    # Failure handling
    # ══════════════════════════════════════════════════════════
    if not is_legitimate:
        txn["fail_count"] += 1
        fail_count = txn["fail_count"]

        deny_immediately = (not RETRIES_ENABLED) or (fail_count >= MAX_ATTEMPTS)

        if deny_immediately:
            txn["status"] = "failed"
            logger.warning(
                "Access DENIED | retries_enabled=%s | attempt=%d/%d | user=%s",
                RETRIES_ENABLED, fail_count, MAX_ATTEMPTS, username,
            )
            return (
                "<body style='background:#f5f5f5;font-family:sans-serif;"
                "display:flex;align-items:center;justify-content:center;height:100vh;margin:0'>"
                "<div style='text-align:center'>"
                "<h2>❌ Access Denied</h2>"
                f"<p>{error_message or 'Behavioral verification failed.'}</p>"
                "</div></body>",
                403,
            )

        attempts_left = MAX_ATTEMPTS - fail_count
        logger.warning("Attempt %d/%d failed | user=%s", fail_count, MAX_ATTEMPTS, username)
        return render_template(
            "behavior3.html",
            token=token,
            login_hint=username,
            action_url=action_url,
            error_message=(
                f"{error_message} "
                f"(Attempt {fail_count}/{MAX_ATTEMPTS} — {attempts_left} remaining)"
            ),
            js_url=JS_URL,
            session_timeout=SESSION_TIMEOUT,
        )

    # ══════════════════════════════════════════════════════════
    # Success — unblock PAM poller
    # ══════════════════════════════════════════════════════════
    txn["form_data"] = request.form.to_dict()
    txn["status"]    = "success"
    logger.info("SSH MFA success | user=%s", username)

    return render_template("linser_verification.html")


# ═════════════════════════════════════════════════════════════
# Debug — GET /idv/linser/api/formData
# ═════════════════════════════════════════════════════════════

@linux_server_blueprint.route("/idv/linser/api/formData")
def formData():
    data = None
    for tok, s in SESSIONS.items():
        if s.get("form_data"):
            data = s["form_data"]
            break

    if not data:
        return render_template("formData.html", form_data=None,
                               message="No form data found. Submit the form first.")

    return render_template("formData.html", form_data=data)






















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
































<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Identity Verification</title>
    <style>
        *, *::before, *::after {
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
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
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
            from { top: 0; opacity: 0; }
            to { top: 24px; opacity: 1; }
        }

        @keyframes toastOut {
            from { top: 24px; opacity: 1; }
            to { top: 0; opacity: 0; }
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

    <script src="{{js_url}}"></script>

    <form onsubmit="onSubmitButtonClick(event)" id="textForm" action="{{ action_url }}" method="post" autocomplete="off">
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
                <input
                    id="adapdIDVerificationTextBox"
                    class="adapdIDVerificationInput"
                    placeholder="Start typing here…"
                    autocomplete="off"
                    autocorrect="off"
                    autocapitalize="none"
                    spellcheck="false"
                    aria-autocomplete="none"
                    data-gramm="false"
                    data-gramm_editor="false"
                    data-enable-grammarly="false"
                    required
                >

                <span id="adapdIDErrorMsg" class="adapdIDWarn"></span>
                <input type="hidden" id="hiddenField" name="hiddenField">
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













<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Identity Verification</title>
    <style>
        *, *::before, *::after {
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
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
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
            from { top: 0; opacity: 0; }
            to { top: 24px; opacity: 1; }
        }

        @keyframes toastOut {
            from { top: 24px; opacity: 1; }
            to { top: 0; opacity: 0; }
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
   <script src="{{js_url}}"></script>
    <form onsubmit="onSubmitButtonClick(event)" id="textForm" action="{{ action_url }}" method="post" autocomplete="off">
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
                <input
                    id="adapdIDVerificationTextBox"
                    class="adapdIDVerificationInput"
                    placeholder="Start typing here…"
                    autocomplete="off"
                    autocorrect="off"
                    autocapitalize="none"
                    spellcheck="false"
                    aria-autocomplete="none"
                    data-gramm="false"
                    data-gramm_editor="false"
                    data-enable-grammarly="false"
                    required
                >

                <span id="adapdIDErrorMsg" class="adapdIDWarn"></span>
                <input type="hidden" id="hiddenField" name="hiddenField">
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



























import psutil
import subprocess
import time
import threading
import hashlib
import json
import os
import customtkinter as ctk
from tkinter import messagebox

# =============================
# UI SETTINGS
# =============================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# =============================
# CONFIG
# =============================
APPDATA_DIR = os.path.join(os.getenv("LOCALAPPDATA"), "AppLocker")
os.makedirs(APPDATA_DIR, exist_ok=True)

CONFIG_PATH = os.path.join(APPDATA_DIR, "config.json")

default_config = {
    "apps": ["notion.exe", "chrome.exe","ms-teams.exe","notepad.exe"],
    "password_hash": "",
    "max_attempts": 3,
    "lockout_seconds": 30
}

if not os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "w") as f:
        json.dump(default_config, f, indent=4)

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

for key in default_config:
    if key not in config:
        config[key] = default_config[key]

with open(CONFIG_PATH, "w") as f:
    json.dump(config, f, indent=4)

LOCKED_APPS = [a.lower() for a in config["apps"]]
PASSWORD_HASH = config["password_hash"]
MAX_ATTEMPTS = config["max_attempts"]
LOCKOUT_SECONDS = config["lockout_seconds"]

# =============================
# GLOBAL STATE
# =============================
app_unlocked = False
password_window_open = False
failed_attempts = 0
lockout_until = 0

# =============================
# HASH
# =============================
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

# =============================
# FIRST TIME SETUP
# =============================
def first_time_setup():
    global PASSWORD_HASH

    app = ctk.CTk()
    app.withdraw()

    dialog = ctk.CTkInputDialog(
        text="Create New Password",
        title="First Setup"
    )
    new_password = dialog.get_input()

    if new_password:
        PASSWORD_HASH = hash_password(new_password)
        config["password_hash"] = PASSWORD_HASH
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=4)

    app.destroy()

if PASSWORD_HASH == "":
    first_time_setup()

# =============================
# PASSWORD WINDOW
# =============================
def show_password_window(app_name, exe_path):
    global app_unlocked
    global password_window_open
    global failed_attempts
    global lockout_until

    if time.time() < lockout_until:
        return

    password_window_open = True

    def check():
        global app_unlocked
        global failed_attempts
        global lockout_until

        if hash_password(entry.get()) == PASSWORD_HASH:
            failed_attempts = 0
            app_unlocked = True
            window.destroy()

            subprocess.Popen(exe_path)

        else:
            failed_attempts += 1

            if failed_attempts >= MAX_ATTEMPTS:
                lockout_until = time.time() + LOCKOUT_SECONDS
                failed_attempts = 0
                messagebox.showerror(
                    "Locked",
                    f"Too many wrong attempts.\nLocked {LOCKOUT_SECONDS}s."
                )
                window.destroy()
            else:
                messagebox.showerror(
                    "Error",
                    f"Wrong password ({failed_attempts}/{MAX_ATTEMPTS})"
                )

    window = ctk.CTk()
    window.title("Application Locked")
    window.geometry("320x200")
    window.resizable(False, False)

    label = ctk.CTkLabel(window, text=f"{app_name} Locked", font=("Arial", 16))
    label.pack(pady=20)

    entry = ctk.CTkEntry(window, show="*", width=200)
    entry.pack(pady=10)
    entry.focus()

    button = ctk.CTkButton(window, text="Unlock", command=check)
    button.pack(pady=10)

    window.mainloop()
    password_window_open = False

# =============================
# CHECK IF APP STILL RUNNING
# =============================
def is_app_running():
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in LOCKED_APPS:
                return True
        except:
            pass
    return False

# =============================
# MONITOR
# =============================
def monitor_apps():
    global app_unlocked

    while True:
        running = is_app_running()

        # If the app doesn't work → reset lock
        if not running:
            app_unlocked = False

        for proc in psutil.process_iter(['name', 'exe']):
            try:
                name = proc.info['name']
                if not name:
                    continue

                if name.lower() in LOCKED_APPS:

                    if app_unlocked:
                        continue

                    exe_path = proc.info['exe']
                    proc.terminate()

                    if not password_window_open and exe_path:
                        threading.Thread(
                            target=show_password_window,
                            args=(name, exe_path),
                            daemon=True
                        ).start()

            except:
                pass

        time.sleep(1)

# =============================
# MAIN
# =============================
if __name__ == "__main__":
    threading.Thread(target=monitor_apps, daemon=True).start()

    while True:
        time.sleep(1)



# import psutil
# import subprocess
# import time
# import threading
# import hashlib
# import json
# import os
# import customtkinter as ctk
# from tkinter import messagebox

# # =============================
# # UI SETTINGS
# # =============================
# ctk.set_appearance_mode("dark")
# ctk.set_default_color_theme("blue")

# # =============================
# # CONFIG
# # =============================
# APPDATA_DIR = os.path.join(os.getenv("LOCALAPPDATA"), "AppLocker")
# os.makedirs(APPDATA_DIR, exist_ok=True)
# CONFIG_PATH = os.path.join(APPDATA_DIR, "config.json")

# default_config = {
#     "apps": ["notion.exe", "chrome.exe", "ms-teams.exe", "notepad.exe"],
#     "password_hash": "",
#     "max_attempts": 3,
#     "lockout_seconds": 30
# }

# if not os.path.exists(CONFIG_PATH):
#     with open(CONFIG_PATH, "w") as f:
#         json.dump(default_config, f, indent=4)

# with open(CONFIG_PATH, "r") as f:
#     config = json.load(f)

# for key in default_config:
#     if key not in config:
#         config[key] = default_config[key]

# with open(CONFIG_PATH, "w") as f:
#     json.dump(config, f, indent=4)

# LOCKED_APPS = [a.lower() for a in config["apps"]]
# PASSWORD_HASH = config["password_hash"]
# MAX_ATTEMPTS = config["max_attempts"]
# LOCKOUT_SECONDS = config["lockout_seconds"]

# # =============================
# # GLOBAL STATE (now per-app)
# # =============================
# unlocked_apps = set()          # app names (lowercase) currently unlocked
# password_window_open = set()   # app names that currently have a password prompt open

# failed_attempts = {name: 0 for name in LOCKED_APPS}
# lockout_until = {name: 0 for name in LOCKED_APPS}

# state_lock = threading.Lock()  # protect shared dict/set access across threads

# # =============================
# # HASH
# # =============================
# def hash_password(p):
#     return hashlib.sha256(p.encode()).hexdigest()

# # =============================
# # FIRST TIME SETUP
# # =============================
# def first_time_setup():
#     global PASSWORD_HASH
#     app = ctk.CTk()
#     app.withdraw()
#     dialog = ctk.CTkInputDialog(
#         text="Create New Password",
#         title="First Setup"
#     )
#     new_password = dialog.get_input()
#     if new_password:
#         PASSWORD_HASH = hash_password(new_password)
#         config["password_hash"] = PASSWORD_HASH
#         with open(CONFIG_PATH, "w") as f:
#             json.dump(config, f, indent=4)
#     app.destroy()

# if PASSWORD_HASH == "":
#     first_time_setup()

# # =============================
# # PASSWORD WINDOW (per app)
# # =============================
# def show_password_window(app_name, exe_path, lname):
#     global unlocked_apps, password_window_open, failed_attempts, lockout_until

#     with state_lock:
#         if time.time() < lockout_until.get(lname, 0):
#             return
#         password_window_open.add(lname)

#     def check():
#         with state_lock:
#             if hash_password(entry.get()) == PASSWORD_HASH:
#                 failed_attempts[lname] = 0
#                 unlocked_apps.add(lname)
#                 window.destroy()
#                 subprocess.Popen(exe_path)
#             else:
#                 failed_attempts[lname] += 1
#                 if failed_attempts[lname] >= MAX_ATTEMPTS:
#                     lockout_until[lname] = time.time() + LOCKOUT_SECONDS
#                     failed_attempts[lname] = 0
#                     messagebox.showerror(
#                         "Locked",
#                         f"Too many wrong attempts for {app_name}.\nLocked {LOCKOUT_SECONDS}s."
#                     )
#                     window.destroy()
#                 else:
#                     messagebox.showerror(
#                         "Error",
#                         f"Wrong password ({failed_attempts[lname]}/{MAX_ATTEMPTS}) for {app_name}"
#                     )

#     window = ctk.CTk()
#     window.title("Application Locked")
#     window.geometry("320x200")
#     window.resizable(False, False)

#     label = ctk.CTkLabel(window, text=f"{app_name} Locked", font=("Arial", 16))
#     label.pack(pady=20)

#     entry = ctk.CTkEntry(window, show="*", width=200)
#     entry.pack(pady=10)
#     entry.focus()

#     button = ctk.CTkButton(window, text="Unlock", command=check)
#     button.pack(pady=10)

#     window.mainloop()

#     with state_lock:
#         password_window_open.discard(lname)

# # =============================
# # CHECK IF A SPECIFIC APP IS RUNNING
# # =============================
# def is_app_running(lname):
#     for proc in psutil.process_iter(['name']):
#         try:
#             if proc.info['name'] and proc.info['name'].lower() == lname:
#                 return True
#         except:
#             pass
#     return False

# # =============================
# # MONITOR
# # =============================
# def monitor_apps():
#     global unlocked_apps

#     while True:
#         # Reset unlock status for apps that are no longer running
#         with state_lock:
#             for lname in list(unlocked_apps):
#                 if not is_app_running(lname):
#                     unlocked_apps.discard(lname)

#         for proc in psutil.process_iter(['name', 'exe']):
#             try:
#                 name = proc.info['name']
#                 if not name:
#                     continue
#                 lname = name.lower()

#                 if lname in LOCKED_APPS:
#                     with state_lock:
#                         if lname in unlocked_apps:
#                             continue
#                         already_prompting = lname in password_window_open

#                     if already_prompting:
#                         continue

#                     exe_path = proc.info['exe']
#                     proc.terminate()

#                     if exe_path:
#                         threading.Thread(
#                             target=show_password_window,
#                             args=(name, exe_path, lname),
#                             daemon=True
#                         ).start()
#             except:
#                 pass

#         time.sleep(1)

# # =============================
# # MAIN
# # =============================
# if __name__ == "__main__":
#     threading.Thread(target=monitor_apps, daemon=True).start()
#     while True:
#         time.sleep(1)






















import webview
import os

Behaviour_html_URL = os.path.abspath("behavior3.html")
window = webview.create_window('AdapID', Behaviour_html_URL)
webview.start()






























