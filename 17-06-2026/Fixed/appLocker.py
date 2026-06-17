import psutil
import subprocess
import time
import threading
import os
import webview
import requests

# =============================
# CONFIG
# =============================
APPDATA_DIR  = os.path.join(os.getenv("LOCALAPPDATA", ""), "AppLockerrrr")
SERVER_BASE  = "https://api357.cf.mandid.link"
GET_HTML_URL = f"{SERVER_BASE}/idv/mandidDesktop/api/getHTML"
COMPLETE_URL = f"{SERVER_BASE}/idv/mandidDesktop/api/complete"

# Apps to lock.  Key = lowercase process name, value = friendly display name.
LOCKED_APPS = {
    "notion.exe":   "Notion",
    "chrome.exe":   "Google Chrome",
    "ms-teams.exe": "Microsoft Teams",
    "notepad.exe":  "Notepad",
}

# Track which apps have already passed verification this session.
# { "chrome.exe": True/False }
is_verified: dict[str, bool] = {app: False for app in LOCKED_APPS}

# Prevent two verification windows opening for the same app at once.
_locks: dict[str, threading.Lock] = {app: threading.Lock() for app in LOCKED_APPS}

# =============================
# VERIFICATION WINDOW
# =============================
def show_mandID_window(app_name: str, exe_path: str) -> None:
    """
    Open a pywebview window that loads the mandID behaviour HTML page
    (with ?app=<app_name> so the server knows which app is being verified).
    After the user submits, the form POSTs to /complete which returns JSON.
    We intercept that JSON inside the webview to decide pass/fail.
    """

    verification_result: dict = {"passed": False}

    # ── JavaScript injected after every page load ──────────────
    # After the form submits the server returns JSON {"status":"success",...}
    # or a 403 HTML page.  We detect this and call window.pywebview.api.done().
    INJECT_JS = """
    (function() {
        // Only run on the /complete response page (not the form page itself)
        var bodyText = document.body ? document.body.innerText : '';
        try {
            var data = JSON.parse(bodyText);
            if (data && data.status === 'success') {
                window.pywebview.api.done(true);
                return;
            }
        } catch(e) {}

        // 403 access-denied page
        if (document.title === '' && bodyText.indexOf('Access Denied') !== -1) {
            window.pywebview.api.done(false);
        }
    })();
    """

    class Api:
        """Exposed to JS as window.pywebview.api"""
        def done(self, passed: bool) -> None:
            verification_result["passed"] = passed
            win.destroy()

    api = Api()

    # Build the URL with the app query param so the server can display
    # "Verifying access to Google Chrome" etc.
    verify_url = f"{GET_HTML_URL}?app={app_name}"

    win = webview.create_window(
        f"mandID — Verify access to {LOCKED_APPS.get(app_name, app_name)}",
        url=verify_url,
        width=520,
        height=600,
        resizable=False,
        on_top=True,
    )

    def on_loaded():
        win.evaluate_js(INJECT_JS)

    win.events.loaded += on_loaded

    # start() blocks until the window is closed
    webview.start(debug=False)

    if verification_result["passed"]:
        print(f"[AppLocker] Verified ✓  Launching {app_name}")
        is_verified[app_name] = True
        subprocess.Popen(exe_path)
    else:
        print(f"[AppLocker] Verification FAILED for {app_name} — not launching.")


# =============================
# MONITOR LOOP
# =============================
def monitor() -> None:
    """Continuously watch for locked apps being launched."""
    print("[AppLocker] Monitor started. Watching:", list(LOCKED_APPS.keys()))
    while True:
        for proc in psutil.process_iter(["name", "exe"]):
            try:
                name = (proc.info["name"] or "").lower()
                if name not in LOCKED_APPS:
                    continue

                # Already verified this session — let it run freely.
                if is_verified[name]:
                    continue

                exe_path = proc.info["exe"] or ""

                # Try to grab the lock non-blocking.
                # If another thread is already showing the window, skip.
                if not _locks[name].acquire(blocking=False):
                    continue

                try:
                    print(f"[AppLocker] Caught {name} — terminating and showing verification.")
                    proc.terminate()
                    # Run the verification window in this thread (webview needs main thread
                    # on some platforms; for multi-app support use separate threads carefully).
                    t = threading.Thread(
                        target=_verify_and_release,
                        args=(name, exe_path),
                        daemon=True,
                    )
                    t.start()
                except Exception as e:
                    print(f"[AppLocker] Error handling {name}: {e}")
                    _locks[name].release()

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        time.sleep(1)


def _verify_and_release(app_name: str, exe_path: str) -> None:
    """Run verification then release the per-app lock."""
    try:
        show_mandID_window(app_name, exe_path)
    finally:
        _locks[app_name].release()


# =============================
# ENTRY POINT
# =============================
if __name__ == "__main__":
    # Ensure data dir exists
    os.makedirs(APPDATA_DIR, exist_ok=True)
    monitor()
