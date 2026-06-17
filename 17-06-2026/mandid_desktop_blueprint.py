#here fix this 
#This is mandid_desktop_blueprint.py
#here in the getHTML take care of app too like for what app we are doing make similar changes in appLocker.py i mean for what is this html teams or chrome or what
#similarly for complete too for what app 
#for now think there is only one user user1 write code accordingly 
#write all three working codes 
# this is rubnning in flask ec2 instance dont worry of starting it it is taken care of just fix this mandid_desktop_blueprint.py
#appLocker.py will be running in endpoint
#behavior4.html is in templates folder of the flask so major of the part i done you need fixing






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
mandid_desktop_blueprint = Blueprint("linux_server_blueprint", __name__)


BEHAVIOUR_DOMAIN = os.getenv("BEHAVIOUR_DOMAIN", "https://api246.cf.mandid.link")
CORE_URL         = os.getenv("CORE_URL",         "/api/PYa2H3FE/v1/sentence/core/encrypt/")
JS_URL           = os.getenv("JS_URL",           "https://api246.cf.mandid.link/api/PYa2H3FE/v1/js/mandtiveSentence/EWnFP0yLQnV")

# ── Config ────────────────────────────────────────────────────
BASE_URL                = os.getenv("BASE_URL",                  "https://api357.cf.mandid.link").rstrip("/")
#BEHAVIOUR_DOMAIN        = os.getenv("BEHAVIOUR_DOMAIN",          "https://api246.cf.mandid.link")
mandID_TENANT_ID        = os.getenv("mandID_TENANT_ID",          "0k6jw4v1-fa10-475b-b7ee-6530e1679f48ag")
mandID_CLIENT_SECRET    = os.getenv("mandID_CLIENT_SECRET",      "8i23ZWF3M1E0SUl3cdqytMxmag")
#CORE_URL = os.getenv("CORE_URL", "/api/PYa2H3FE/v1/sentence/core/encrypt/")
#JS_URL   = os.getenv("JS_URL",   "/api/PYa2H3FE/v1/js/mandtiveSentence/EWnFP0yLQnVag")
# CORE_URL                = os.getenv("CORE_URL",                  "https://api246.cf.mandid.link/api/PYa2H3FE/v1/sentence/core/encrypt/")
# JS_URL                  = os.getenv("JS_URL",                    "https://api246.cf.mandid.link/api/PYa2H3FE/v1/js/mandtiveSentence/EWnFP0yLQnVag")
DB_NAME                 = os.getenv("DB_NAME",                   "linux_mfa")
SESSION_TIMEOUT         = int(os.getenv("SESSION_TIMEOUT",       "120"))
MAX_ATTEMPTS            = int(os.getenv("MAX_BEHAVIOUR_ATTEMPTS","3"))
#ENROLLMENT_PASS_THROUGH = os.getenv("ENROLLMENT_PASS_THROUGH",  "true").strip().lower() == "true"
ENROLLMENT_PASS_THROUGH=True
RETRIES_ENABLED         = os.getenv("RETRIES_ENABLED",           "false").strip().lower() == "true"



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
# ═════════════════════════════════════════════════════════════

@mandid_desktop_blueprint.route("/idv/mandidDesktop/api/getHTML", methods=["GET"])
def getHTML():
    action_url = f"{BASE_URL}/idv/mandidDesktop/api/complete"
    return render_template(
        "behavior4.html",
        login_hint="user1",#For now Adjust
        error_message=None,
        action_url=action_url,
        js_url=JS_URL,
        session_timeout=SESSION_TIMEOUT,
    )


# ═════════════════════════════════════════════════════════════
# Browser — POST /idv/mandidDesktop/api/complete
# ═════════════════════════════════════════════════════════════

@mandid_desktop_blueprint.route("/idv/mandidDesktop/api/complete", methods=["POST"])
def mfa_submit():
    username   ="user1",#For now Adjust
    action_url = f"{BASE_URL}/idv/mandidDesktop/api/complete"

    # ── Parse hiddenField ──────────────────────────────────────
    user_input = request.form.get("hiddenField", "")
    if not user_input:
        return render_template(
            "behavior4.html",
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
            "behavior4.html",
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
            "behavior4.html",
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
        auth_key=authkey,
        tenant_id=mandID_TENANT_ID,
        core_url=CORE_URL,
        client_secret=mandID_CLIENT_SECRET,
    )
    print("*"*80)
    logger.info("core is %s", core)
    #print(core)
    print("*"*80)
    if core is None:
        return render_template(
            "behavior4.html",
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
                "idp":                 "mandidDesktop",
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
                    "behavior4.html",
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
            "idp":                 "mandidDesktop",
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
        deny_immediately = (not RETRIES_ENABLED)  

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
            "behavior4.html",
            login_hint=username,
            action_url=action_url,
            error_message=(
                f"{error_message} "
                f"(Attempt {fail_count}/{MAX_ATTEMPTS} — {attempts_left} remaining)"
            ),
            js_url=JS_URL,
            session_timeout=SESSION_TIMEOUT,
        )

    txn["form_data"] = request.form.to_dict()
    txn["status"]    = "success"
    logger.info("SSH MFA success | user=%s", username)

    return render_template("linser_verification.html")


# ═════════════════════════════════════════════════════════════
# Debug — GET /idv/mandidDesktop/api/formData
# ═════════════════════════════════════════════════════════════

@mandid_desktop_blueprint.route("/idv/mandidDesktop/api/formData")
def formData():
    data = None
    for tok, s in SESSIONS.items():
        if s.get("form_data"):
            data = s["form_data"]
            break

    if not data:
        return render_template("formData.html", form_data=None,
                               message="No form data found. Submit the form first.")

    return render_template("formData2.html", form_data=data)


