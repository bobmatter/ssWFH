"""
Linux SSH Behavioral Biometrics MFA Server
Flow: PAM → POST /idv/linser/api/create_session
      → GET  /idv/linser/api/mfa/<token>   (browser)
      → POST /idv/linser/api/complete/<token>
      → PAM polls /idv/linser/api/status/<token>
"""

import os
import time
import secrets
import logging
import requests

from flask import Blueprint, request, jsonify, render_template, current_app

# ── Blueprint ─────────────────────────────────────────────────
linux_server_blueprint = Blueprint("linux_server_blueprint", __name__)

# ── Logging ───────────────────────────────────────────────────
#os.makedirs("/logs", exist_ok=True)

logging.basicConfig( level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[ logging.FileHandler("/logs/linser_mfa_server.log"),
        logging.StreamHandler(),
    ], )
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────
BASE_URL                = os.getenv("BASE_URL",                  "https://api357.cf.adapid.link").rstrip("/")
BEHAVIOUR_API_URL       = os.getenv("BEHAVIOUR_API_URL",         "")   # provide this
BEHAVIOUR_JS_URL        = os.getenv("BEHAVIOUR_JS_URL",          "")   # provide this
BEHAVIOUR_DB_NAME       = os.getenv("BEHAVIOUR_DB_NAME",         "linux_mfa")
SESSION_TIMEOUT         = int(os.getenv("SESSION_TIMEOUT",       "120"))
MAX_ATTEMPTS            = int(os.getenv("MAX_BEHAVIOUR_ATTEMPTS","3"))
ENROLLMENT_PASS_THROUGH = os.getenv("ENROLLMENT_PASS_THROUGH",  "true").strip().lower() == "true"
RETRIES_ENABLED         = os.getenv("RETRIES_ENABLED",           "false").strip().lower() == "true"

# ── In-memory session store ───────────────────────────────────
SESSIONS: dict = {}


def _clean_sessions():
    now  = time.time()
    dead = [t for t, s in SESSIONS.items() if now - s["created_at"] > SESSION_TIMEOUT + 60]
    for t in dead:
        del SESSIONS[t]


# ── Behaviour API helpers ─────────────────────────────────────
def enqueue_behaviour_log(record: dict, db_name: str = ""):
    logger.info("behaviour_log | db=%s | record=%s", db_name, record)


def call_behaviour_check(behaviour_data: dict, username: str) -> dict | None:
    """POST keystroke data to the behaviour API. Returns parsed JSON or None."""
    if not BEHAVIOUR_API_URL:
        logger.warning("BEHAVIOUR_API_URL not set — skipping behaviour check")
        return None
    headers = {"Content-Type": "application/json"}
    payload = {"username": username, **behaviour_data}
    try:
        resp = requests.post(BEHAVIOUR_API_URL, json=payload, headers=headers, timeout=30)
        if resp.status_code != 200:
            logger.error("Behaviour API %d | body=%s", resp.status_code, resp.text[:500])
            return None
        return resp.json()
    except Exception as exc:
        logger.error("Behaviour API failed | error=%s", exc)
        return None

@linux_server_blueprint.route("/idv/linser/api/healtz", methods=["GET"])
def health():
    return """
    <html>
        <body>
            <h1>Hello </h1>
            <p>Linux MFA Server is running.</p>
        </body>
    </html>
    """

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
        "phrase":     "",          # phrase generation is handled in behavior.html
        "status":     "pending",   # pending | success | failed
        "behaviour":  None,
        "db_name":    BEHAVIOUR_DB_NAME,
        "fail_count": 0,
        "created_at": time.time(),
    }

    mfa_url = f"{BASE_URL}/idv/linser/api/mfa/{token}"
    logger.info("Session created | user=%s | token=%s…", username, token[:8])
    return jsonify({"token": token, "mfa_url": mfa_url})


# ═════════════════════════════════════════════════════════════
# PAM API — GET /idv/linser/api/status/<token>  (polled every 2 s)
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

    submit_url = f"{BASE_URL}/idv/linser/api/complete/{token}"
    return render_template(
        "behavior.html",
        token=token,
        login_hint=s["username"],
        phrase=s.get("phrase", ""),
        error_message=None,
        submit_url=submit_url,
        js_url=BEHAVIOUR_JS_URL,
        session_timeout=SESSION_TIMEOUT,
    )

# ═════════════════════════════════════════════════════════════
# Browser — POST /idv/linser/api/complete/<token>
# Receives JSON: { typed, phrase, behaviourData }
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
    db_name    = txn["db_name"]
    fail_count = txn["fail_count"]

    data           = request.get_json(silent=True) or {}
    typed          = data.get("typed", "").strip()
    phrase         = data.get("phrase", "").strip()
    behaviour_data = data.get("behaviourData", {})

    if not typed:
        return jsonify({"success": False, "retry": True, "error": "No phrase received. Please try again."})
    if not behaviour_data:
        return jsonify({"success": False, "retry": True, "error": "No behavioral data received. Please try again."})

    # ── Phrase check ──────────────────────────────────────────
    if typed.lower() != phrase.lower():
        fail_count += 1
        txn["fail_count"] = fail_count
        deny = (not RETRIES_ENABLED) or (fail_count >= MAX_ATTEMPTS)
        if deny:
            txn["status"] = "failed"
            logger.warning("DENIED — wrong phrase | user=%s | attempt=%d", username, fail_count)
            return jsonify({"success": False, "error": "Wrong passphrase. Access denied."})
        left = MAX_ATTEMPTS - fail_count
        logger.warning("Wrong phrase %d/%d | user=%s", fail_count, MAX_ATTEMPTS, username)
        return jsonify({"success": False, "retry": True,
                        "error": f"Wrong passphrase ({left} attempt(s) remaining)"})

    # ── Behaviour API ─────────────────────────────────────────
    core = call_behaviour_check(behaviour_data=behaviour_data, username=username)
    if core is None:
        if ENROLLMENT_PASS_THROUGH:
            logger.warning("Behaviour API unavailable — ALLOWED (pass-through) | user=%s", username)
            txn["status"] = "success"
            return jsonify({"success": True})
        txn["status"] = "failed"
        logger.error("Behaviour API unavailable — DENIED | user=%s", username)
        return jsonify({"success": False, "error": "Unable to verify behavioral data."})

    # ── Parse API response ────────────────────────────────────
    timestamp          = int(time.time())
    behavioural_status = "Unknown"
    user_type          = "Unknown"
    is_legitimate      = False
    error_message      = None
    already_logged     = False

    if "message" in core:
        message = core.get("message", "")
        if message == "Insufficient data to create profile":
            record = {
                "idp_transaction_id":  token,
                "username":            username,
                "message":             message,
                "idp":                 "linux_ssh",
                "behavioral_status":   "Insufficient data",
                "combined_risk_score": core.get("combined_risk_score", 0),
                "behavior_success":    core.get("isSuccess", "False"),
                "user_type":           "New",
                "auth_time_iso":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
            }
            enqueue_behaviour_log(record, db_name=db_name)
            already_logged = True
            if ENROLLMENT_PASS_THROUGH:
                logger.info("Insufficient data — ALLOWED (pass-through) | user=%s", username)
                is_legitimate = True
            else:
                return jsonify({"success": False, "retry": True,
                                "error": "Please type the phrase again to complete your profile setup."})
        elif message == "Profile got created":
            behavioural_status = "Profile created"
            user_type          = "New"
            is_legitimate      = True
            logger.info("Profile created — allowed | user=%s", username)
        else:
            error_message = f"Authentication failed: {message}."

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
            logger.warning("BLOCKED — step up | user=%s", username)
        else:
            behavioural_status = bb
            user_type          = "unknown"
            error_message      = "Login failed. Unusual behavior detected."
            logger.warning("BLOCKED — unusual | user=%s | status=%s", username, bb)

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

    temp_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
    if not already_logged:
        record = {
            "idp_transaction_id":  token,
            "username":            username,
            "message":             core.get("message", ""),
            "idp":                 "linux_ssh",
            "behavioral_status":   behavioural_status,
            "combined_risk_score": core.get("combined_risk_score", 0),
            "behavior_success":    core.get("isSuccess", "False"),
            "user_type":           user_type,
            "auth_time_iso":       temp_timestamp,
        }
        enqueue_behaviour_log(record, db_name=db_name)

    # ── Failure handling ──────────────────────────────────────
    if not is_legitimate:
        fail_count += 1
        txn["fail_count"] = fail_count
        deny = (not RETRIES_ENABLED) or (fail_count >= MAX_ATTEMPTS)
        if deny:
            txn["status"] = "failed"
            denial_reason = (
                f"Behavioral verification failed after {MAX_ATTEMPTS} attempt(s)."
                if RETRIES_ENABLED
                else error_message or "Behavioral verification failed."
            )
            logger.warning("Access DENIED | user=%s | attempt=%d/%d", username, fail_count, MAX_ATTEMPTS)
            return jsonify({"success": False, "error": denial_reason})
        left = MAX_ATTEMPTS - fail_count
        return jsonify({
            "success": False, "retry": True,
            "error": f"{error_message} (Attempt {fail_count}/{MAX_ATTEMPTS} — {left} remaining)",
        })

    # ── Success ───────────────────────────────────────────────
    txn["status"] = "success"
    logger.info("MFA SUCCESS | user=%s | status=%s | token=%s…", username, behavioural_status, token[:8])
    return jsonify({"success": True})


# ═════════════════════════════════════════════════════════════
# Health & Debug
# ═════════════════════════════════════════════════════════════
@linux_server_blueprint("/idv/linser/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "sessions": len(SESSIONS), "ts": int(time.time())})


@linux_server_blueprint.route("/idv/linser/api/behaviour/<token>", methods=["GET"])
def get_behaviour(token):
    s = SESSIONS.get(token)
    if not s or not s.get("behaviour"):
        return jsonify({"error": "not found"}), 404
    return jsonify(s["behaviour"])