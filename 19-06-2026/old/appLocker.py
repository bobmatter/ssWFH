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


#This is the app Locker

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
SERVER_BASE = ""
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
