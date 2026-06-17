import os
import time
import json
import logging
import requests
from flask import Blueprint, request, jsonify, render_template

logger = logging.getLogger(__name__)

# ── Blueprint ─────────────────────────────────────────────────
mandid_desktop_blueprint = Blueprint("linux_server_blueprint", __name__)

BEHAVIOUR_DOMAIN = os.getenv("BEHAVIOUR_DOMAIN", "https://api246.cf.mandid.link")
CORE_URL         = os.getenv("CORE_URL",         "/api/PYa2H3FE/v1/sentence/core/encrypt/")
JS_URL           = os.getenv("JS_URL",            "https://api246.cf.mandid.link/api/PYa2H3FE/v1/js/mandtiveSentence/EWnFP0yLQnV")

BASE_URL             = os.getenv("BASE_URL",             "https://api357.cf.mandid.link").rstrip("/")
mandID_TENANT_ID     = os.getenv("mandID_TENANT_ID",     "0k6jw4v1-fa10-475b-b7ee-6530e1679f48ag")
mandID_CLIENT_SECRET = os.getenv("mandID_CLIENT_SECRET", "8i23ZWF3M1E0SUl3cdqytMxmag")

DB_NAME             = os.getenv("DB_NAME",                    "linux_mfa")
SESSION_TIMEOUT     = int(os.getenv("SESSION_TIMEOUT",        "120"))
MAX_ATTEMPTS        = int(os.getenv("MAX_BEHAVIOUR_ATTEMPTS", "3"))
ENROLLMENT_PASS_THROUGH = True
RETRIES_ENABLED     = os.getenv("RETRIES_ENABLED", "false").strip().lower() == "true"

# ── Fixed username (one user for now) ─────────────────────────
FIXED_USERNAME = "user1"

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
@mandid_desktop_blueprint.route("/idv/mandidDesktop/api/health", methods=["GET"])
def health():
    return """
    <html><body>
        <h1>Hello</h1>
        <p>mandID Server is running.</p>
    </body></html>
    """


# ═════════════════════════════════════════════════════════════
# Browser — GET /idv/mandidDesktop/api/getHTML/
# Expects ?app=chrome.exe (or whichever locked app triggered this)
# ═════════════════════════════════════════════════════════════
@mandid_desktop_blueprint.route("/idv/mandidDesktop/api/getHTML", methods=["GET"])
def getHTML():
    # Which app triggered this verification?
    app_name = request.args.get("app", "").lower().strip()
    app_display = APP_DISPLAY_NAMES.get(app_name, app_name if app_name else "Application")

    action_url = f"{BASE_URL}/idv/mandidDesktop/api/complete"

    return render_template(
        "behavior4.html",
        login_hint=FIXED_USERNAME,
        error_message=None,
        action_url=action_url,
        js_url=JS_URL,
        session_timeout=SESSION_TIMEOUT,
        app_name=app_name,
        app_display=app_display,
    )


# ═════════════════════════════════════════════════════════════
# Browser — POST /idv/mandidDesktop/api/complete
# ═════════════════════════════════════════════════════════════
@mandid_desktop_blueprint.route("/idv/mandidDesktop/api/complete", methods=["POST"])
def mfa_submit():
    username   = FIXED_USERNAME
    action_url = f"{BASE_URL}/idv/mandidDesktop/api/complete"

    # Which app was being unlocked? Sent as a hidden field from the form.
    app_name    = request.form.get("app_name", "").lower().strip()
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
        tenant_id=mandID_TENANT_ID,
        core_url=CORE_URL,
        client_secret=mandID_CLIENT_SECRET,
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
                "idp":                 "mandidDesktop",
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
            "idp":                 "mandidDesktop",
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
