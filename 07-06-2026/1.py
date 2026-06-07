/*
 * pam_mfa.c — Behavioral Biometrics MFA PAM module
 *
 * Build:
 *   gcc -fPIC -shared -o pam_mfa.so pam_mfa.c -lpam
 *
 * Install:
 *   cp pam_mfa.so /lib/x86_64-linux-gnu/security/
 *
 * Flow:
 *   POST MFA_HOST/idv/linser/api/create_session  → {token, mfa_url}
 *   show mfa_url to user
 *   poll MFA_HOST/idv/linser/api/status/<token>  → {status}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* ── Config — edit MFA_HOST before compiling ──────────────── */
#define MFA_HOST        "https://api357.cf.mandy.link"
#define POLL_INTERVAL   2      /* seconds between status polls */
#define POLL_TIMEOUT    120    /* total wait seconds           */

/* ── curl POST: writes body to temp file, returns bytes read ─ */
static int curl_post(const char *url, const char *body,
                     char *out, size_t out_len)
{
    FILE *f = fopen("/tmp/mfa_req.json", "w");
    if (!f) return -1;
    fprintf(f, "%s", body);
    fclose(f);

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "curl -s --max-time 10 --connect-timeout 5 "
        "-X POST '%s' "
        "-H 'Content-Type: application/json' "
        "--data-binary @/tmp/mfa_req.json",
        url);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    size_t n = fread(out, 1, out_len - 1, fp);
    out[n] = '\0';
    pclose(fp);
    return (int)n;
}

/* ── curl GET ─────────────────────────────────────────────── */
static int curl_get(const char *url, char *out, size_t out_len)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "curl -s --max-time 5 --connect-timeout 3 '%s'",
        url);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    size_t n = fread(out, 1, out_len - 1, fp);
    out[n] = '\0';
    pclose(fp);
    return (int)n;
}

/* ── Minimal JSON string value extractor ─────────────────── */
static int json_get_str(const char *json, const char *key,
                        char *out, size_t out_len)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":\"", key);

    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);

    const char *end = strchr(p, '"');
    if (!end) return 0;

    size_t len = (size_t)(end - p);
    if (len >= out_len) len = out_len - 1;
    strncpy(out, p, len);
    out[len] = '\0';
    return 1;
}

/* ── PAM authenticate ────────────────────────────────────── */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    const char *username = NULL;
    char buf[4096];
    char token[128];
    char mfa_url[512];
    char status[32];

    pam_get_user(pamh, &username, NULL);
    if (!username || strcmp(username, "root") == 0)
        return PAM_SUCCESS;

    /* ── Step 1: Create session ─────────────────────────── */
    char create_url[512];
    snprintf(create_url, sizeof(create_url),
             MFA_HOST "/idv/linser/api/create_session");

    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\"}", username);

    int n = curl_post(create_url, body, buf, sizeof(buf));
    if (n <= 0) {
        pam_error(pamh, "MFA: server not reachable (%s)", MFA_HOST);
        return PAM_AUTH_ERR;
    }

    if (!json_get_str(buf, "token",   token,   sizeof(token)) ||
        !json_get_str(buf, "mfa_url", mfa_url, sizeof(mfa_url))) {
        pam_error(pamh, "MFA: unexpected server response: %.200s", buf);
        return PAM_AUTH_ERR;
    }

    /* ── Step 2: Show URL to user ───────────────────────── */
    pam_info(pamh, " ");
    pam_info(pamh, "╔══════════════════════════════════════════════════╗");
    pam_info(pamh, "║          MFA VERIFICATION REQUIRED               ║");
    pam_info(pamh, "╠══════════════════════════════════════════════════╣");
    pam_info(pamh, "║  Open this URL in your browser:                  ║");
    pam_info(pamh, "║                                                  ║");
    pam_info(pamh, "  %s", mfa_url);
    pam_info(pamh, "║                                                  ║");
    pam_info(pamh, "║  Type the phrase shown on the page.              ║");
    pam_info(pamh, "║  This terminal will unlock automatically.        ║");
    pam_info(pamh, "╚══════════════════════════════════════════════════╝");
    pam_info(pamh, "  Waiting for browser verification (%ds)...", POLL_TIMEOUT);
    pam_info(pamh, " ");

    /* ── Step 3: Poll status ────────────────────────────── */
    char status_url[512];
    snprintf(status_url, sizeof(status_url),
             MFA_HOST "/idv/linser/api/status/%s", token);

    int elapsed = 0;
    while (elapsed < POLL_TIMEOUT) {
        sleep(POLL_INTERVAL);
        elapsed += POLL_INTERVAL;

        char resp[512];
        if (curl_get(status_url, resp, sizeof(resp)) <= 0) continue;
        if (!json_get_str(resp, "status", status, sizeof(status))) continue;

        if (strcmp(status, "success") == 0) {
            pam_info(pamh, "  [OK] Browser verification successful!");
            return PAM_SUCCESS;
        }

        if (strcmp(status, "failed") == 0 || strcmp(status, "expired") == 0) {
            pam_error(pamh, "  [X] MFA verification %s.", status);
            return PAM_AUTH_ERR;
        }

        /* Show progress every 10 s */
        if (elapsed % 10 == 0) {
            char waiting[80];
            snprintf(waiting, sizeof(waiting),
                     "  Still waiting... (%d/%ds)", elapsed, POLL_TIMEOUT);
            pam_info(pamh, "%s", waiting);
        }
    }

    pam_error(pamh, "  [X] MFA timed out. Please SSH again.");
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv)

{
    return PAM_SUCCESS;
}










#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  install.sh — Linux SSH Behavioral MFA client setup
#  Runs ONLY on the client EC2 (e.g. 51.20.51.174)
#  The MFA Flask server is on a completely separate instance.
#
#  Usage:
#      sudo bash install.sh
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✔]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[✘]${NC} $1"; exit 1; }

[ "$EUID" -ne 0 ] && fail "Run as root: sudo bash install.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAM_C="$SCRIPT_DIR/pam_mfa.c"
PAM_SO_TMP="/tmp/pam_mfa.so"
PAM_SO_DEST="/lib/x86_64-linux-gnu/security/pam_mfa.so"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "   Linux SSH Behavioral MFA — Client Installer"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ═══════════════════════════════════════════════════════════════════
# STEP 1: Install dependencies
# ═══════════════════════════════════════════════════════════════════
log "Updating package list..."
apt-get update -qq

log "Installing gcc and libpam0g-dev..."
apt-get install -y -qq gcc libpam0g-dev

# ═══════════════════════════════════════════════════════════════════
# STEP 2: Compile and install PAM module
# ═══════════════════════════════════════════════════════════════════
[ -f "$PAM_C" ] || fail "pam_mfa.c not found at $PAM_C"

log "Compiling PAM module..."
gcc -fPIC -shared \
    -o "$PAM_SO_TMP" \
    "$PAM_C" \
    -lpam

cp "$PAM_SO_TMP" "$PAM_SO_DEST"
chmod 644 "$PAM_SO_DEST"
log "PAM module installed → $PAM_SO_DEST"

# ═══════════════════════════════════════════════════════════════════
# STEP 3: Configure PAM for SSH
# ═══════════════════════════════════════════════════════════════════
log "Backing up /etc/pam.d/sshd..."
cp /etc/pam.d/sshd "/etc/pam.d/sshd.bak.$(date +%s)"

log "Writing /etc/pam.d/sshd..."
cat > /etc/pam.d/sshd << 'PAM'
# Step 1: Standard Unix password check
auth    required    pam_unix.so nullok
# Step 2: Behavioral biometrics MFA (browser-based)
auth    required    pam_mfa.so
# Step 3: Allow through
auth    required    pam_permit.so

account required    pam_nologin.so
@include common-account

session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
session required    pam_loginuid.so
session optional    pam_keyinit.so force revoke
@include common-session
session optional    pam_motd.so motd=/run/motd.dynamic
session optional    pam_motd.so noupdate
session optional    pam_mail.so standard noenv
session required    pam_limits.so
session required    pam_env.so
session required    pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open

@include common-password
PAM

log "/etc/pam.d/sshd written"

# ═══════════════════════════════════════════════════════════════════
# STEP 4: Configure sshd_config
# ═══════════════════════════════════════════════════════════════════
log "Configuring /etc/ssh/sshd_config..."
SSHD_CONF=/etc/ssh/sshd_config

# UsePAM yes
if grep -q "^UsePAM" "$SSHD_CONF"; then
    sed -i 's/^UsePAM.*/UsePAM yes/' "$SSHD_CONF"
else
    echo "UsePAM yes" >> "$SSHD_CONF"
fi

# PasswordAuthentication yes  (so PAM gets invoked)
if grep -q "^PasswordAuthentication" "$SSHD_CONF"; then
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONF"
else
    echo "PasswordAuthentication yes" >> "$SSHD_CONF"
fi

# ChallengeResponseAuthentication yes
if grep -q "^ChallengeResponseAuthentication" "$SSHD_CONF"; then
    sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "$SSHD_CONF"
else
    echo "ChallengeResponseAuthentication yes" >> "$SSHD_CONF"
fi

log "sshd_config updated"

# ═══════════════════════════════════════════════════════════════════
# STEP 5: Restart SSH
# ═══════════════════════════════════════════════════════════════════
log "Restarting SSH..."
systemctl restart ssh
log "SSH restarted"

# ═══════════════════════════════════════════════════════════════════
# Done
# ═══════════════════════════════════════════════════════════════════
# Edit this to your actual MFA server base URL (for display only)
MFA_SERVER="https://api357.cf.mandy.link"
PUBLIC_IP=$(curl -sf http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "this-server")

echo ""
echo "═══════════════════════════════════════════════════════════"
echo -e "  ${GREEN}Installation complete!${NC}"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  PAM module:  $PAM_SO_DEST"
echo "  MFA server:  $MFA_SERVER"
echo "  Health:      $MFA_SERVER/idv/linser/api/health"
echo ""
echo "  Test (from a DIFFERENT terminal — keep this one open):"
echo "      ssh ubuntu@$PUBLIC_IP"
echo "      → enter password"
echo "      → open the MFA URL shown in your terminal"
echo "      → type phrase in browser → SSH opens!"
echo ""
warn "Keep this SSH session open until you confirm another session works!"
echo ""


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
os.makedirs("/logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/logs/linser_mfa_server.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────
BASE_URL                = os.getenv("BASE_URL",                  "https://api357.cf.adapid.link").rstrip("/")
BEHAVIOUR_API_URL       = os.getenv("BEHAVIOUR_API_URL",         "")   # you will provide this
BEHAVIOUR_JS_URL        = os.getenv("BEHAVIOUR_JS_URL",          "")   # you will provide this
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





