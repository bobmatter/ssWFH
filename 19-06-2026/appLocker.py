import os
import sys
import time
import signal
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
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
SERVER_BASE = ""
GET_HTML_URL = f"{SERVER_BASE}/idv/adapidDesktop/api/getHTML"
COMPLETE_URL = f"{SERVER_BASE}/idv/adapidDesktop/api/complete"
USERNAME = getpass.getuser()

# Apps that ALWAYS require MFA, no matter where they're launched from.
# Key = lowercase process name, value = friendly display name.
LOCKED_APPS = {
    "notion.exe": "Notion",
    "chrome.exe": "Google Chrome",
    "ms-teams.exe": "Microsoft Teams",
    "notepad.exe": "Notepad",
}

# Path prefixes that are NEVER subject to MFA (OS internals etc).
# Checked case-insensitively, with normalized separators.
TRUSTED_PATH_PREFIXES = [
    r"C:\Windows\\",
]

# Path categories that get MFA, but share a grace period -- once ANY app
# under that prefix is verified, the whole category is exempt until the
# grace period expires.
#
# Order matters: more specific prefixes must come before more general ones
# (e.g. WindowsApps is a subfolder of Program Files, so it's listed first).
GRACE_PATH_CATEGORIES = [
    (r"C:\Program Files\WindowsApps\\", "windowsapps"),
    (r"C:\Program Files (x86)\\", "program_files_x86"),
    (r"C:\Program Files\\", "program_files"),
]

GRACE_PERIOD = timedelta(minutes=90)
VERIFY_TIMEOUT = 300  # seconds a verification window may stay open
POLL_INTERVAL = 1.0   # seconds between process-table scans


# =============================
# LOGGING
# =============================
def setup_logging() -> logging.Logger:
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
        if sys.stdout is not None:
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
# DOMAIN MODEL
# =============================
class Decision:
    """Possible outcomes of the policy check."""
    ALLOW = "ALLOW"          # never needs MFA (trusted system path)
    REQUIRE_MFA = "REQUIRE_MFA"
    SKIP_GRACE = "SKIP_GRACE"  # needs MFA normally, but grace window covers it


@dataclass
class Application:
    """Represents one tracked process instance."""
    name: str            # lowercase exe name, e.g. "chrome.exe"
    pid: int
    exe_path: str
    category: str = ""          # "trusted" / "program_files" / "windowsapps" / etc.
    is_locked_app: bool = False  # True if in LOCKED_APPS (always needs MFA)
    last_verified: datetime | None = None  # when MFA last passed for THIS pid
    verified: bool = False

    def mark_verified(self):
        self.verified = True
        self.last_verified = datetime.now()

    def is_still_running(self) -> bool:
        return psutil.pid_exists(self.pid)


class PathPolicy:
    """Decides whether a given exe path/name needs MFA, and which grace
    category (if any) it belongs to."""

    @staticmethod
    def _normalize(path: str) -> str:
        return (path or "").strip().lower()

    @classmethod
    def classify(cls, name: str, exe_path: str) -> tuple[str, str]:
        """
        Returns (decision_type, category) where decision_type is one of:
        "trusted", "locked_always", "grace", "default"
        """
        name = (name or "").lower()
        norm_path = cls._normalize(exe_path)

        # Locked apps ALWAYS require MFA, regardless of path.
        if name in LOCKED_APPS:
            return "locked_always", "locked"

        # Trusted system paths never need MFA.
        for prefix in TRUSTED_PATH_PREFIXES:
            if norm_path.startswith(prefix.lower()):
                return "trusted", "trusted"

        # Grace-period categories (Program Files, Program Files (x86),
        # WindowsApps). Checked in order so subfolders win over parents.
        for prefix, category in GRACE_PATH_CATEGORIES:
            if norm_path.startswith(prefix.lower()):
                return "grace", category

        # Anything else: MFA every single time, no grace.
        return "default", "default"


class GraceTracker:
    """
    Tracks, per category, the last time ANY app in that category passed MFA.
    Thread-safe since monitor() runs on a worker thread while verification
    windows are created on demand.
    """

    def __init__(self):
        self._last_verified_at: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def record_pass(self, category: str):
        with self._lock:
            self._last_verified_at[category] = datetime.now()

    def is_in_grace(self, category: str) -> bool:
        with self._lock:
            ts = self._last_verified_at.get(category)
        if ts is None:
            return False
        return datetime.now() - ts < GRACE_PERIOD


# =============================
# VERIFICATION (runs on the monitor worker thread, NOT a subprocess)
# =============================
def show_verification(app_name: str, shutdown_event: threading.Event) -> bool:
    """
    Create a verification window on demand and block (this thread only) until
    it resolves, the user closes it, it times out, or shutdown is requested.
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
        def done(self, passed):
            result["passed"] = bool(passed)
            logger.info("Page called done(passed=%s) for %s", passed, app_name)
            _destroy()

    def _destroy():
        try:
            win.destroy()
        except Exception:
            pass

    verify_url = f"{GET_HTML_URL}?app={app_name}&username={USERNAME}"
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

    deadline = time.time() + VERIFY_TIMEOUT
    last_state = None
    while not closed.is_set() and not shutdown_event.is_set() and time.time() < deadline:
        try:
            state = win.evaluate_js(CHECK_JS)
        except Exception:
            state = None

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
        if shutdown_event.is_set():
            logger.info("Verification for %s aborted (shutdown).", app_name)
        elif time.time() >= deadline:
            logger.warning("Verification TIMED OUT for %s", app_name)
        _destroy()

    closed.wait(timeout=5)
    logger.info("Verification window closed for %s. passed=%s", app_name, result["passed"])
    return result["passed"]


# =============================
# RELAUNCH
# =============================
def relaunch_app(app_name: str, exe_path: str) -> None:
    logger = logging.getLogger("AppLocker")

    if not exe_path or not os.path.exists(exe_path):
        logger.warning(
            "Cannot relaunch %s: exe path missing/invalid (%r)", app_name, exe_path
        )
        return

    logger.info("Relaunching %s from %s", app_name, exe_path)
    try:
        os.startfile(exe_path)
        return
    except Exception:
        logger.exception("os.startfile failed for %s, trying Popen", app_name)

    try:
        import subprocess
        subprocess.Popen([exe_path], cwd=os.path.dirname(exe_path) or None)
    except Exception:
        logger.exception("Popen relaunch also failed for %s", app_name)


# =============================
# MONITOR
# =============================
class Monitor:
    """
    Owns the live table of tracked Application instances and runs the
    polling loop that decides, for each process, whether MFA is required.
    """

    def __init__(self, shutdown_event: threading.Event):
        self.logger = logging.getLogger("AppLocker")
        self.shutdown_event = shutdown_event
        self.grace = GraceTracker()
        # key = pid -> Application, so we can tell "same instance still
        # running" apart from "closed and relaunched".
        self.tracked: dict[int, Application] = {}

    def _decide(self, app: Application) -> str:
        """Returns one of Decision.ALLOW / REQUIRE_MFA / SKIP_GRACE."""
        decision_type, category = PathPolicy.classify(app.name, app.exe_path)
        app.category = category

        if decision_type == "trusted":
            return Decision.ALLOW

        if decision_type == "locked_always":
            return Decision.REQUIRE_MFA

        if decision_type == "grace":
            if self.grace.is_in_grace(category):
                return Decision.SKIP_GRACE
            return Decision.REQUIRE_MFA

        # "default" -- MFA every time, no grace, no exceptions.
        return Decision.REQUIRE_MFA

    def _handle_new_process(self, name: str, pid: int, exe_path: str):
        app = Application(name=name, pid=pid, exe_path=exe_path)
        decision = self._decide(app)

        if decision == Decision.ALLOW:
            # Trusted system path -- don't even log noisily, just track it
            # so we don't re-evaluate it every poll cycle.
            self.tracked[pid] = app
            return

        if decision == Decision.SKIP_GRACE:
            self.logger.info(
                "%s (pid=%s) in category '%s' is within grace period -- skipping MFA.",
                name, pid, app.category,
            )
            app.mark_verified()
            self.tracked[pid] = app
            return

        # Decision.REQUIRE_MFA -- terminate, verify, relaunch if passed.
        self.logger.info(
            "%s (pid=%s) requires MFA [category=%s]. Terminating and verifying.",
            name, pid, app.category,
        )
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=5)
            self.logger.debug("Terminated %s", name)
        except Exception:
            self.logger.exception("Problem terminating %s", name)

        passed = show_verification(name, self.shutdown_event)

        if passed:
            app.mark_verified()
            self.grace.record_pass(app.category)
            self.tracked[pid] = app
            relaunch_app(name, exe_path)
        else:
            self.logger.info("Not relaunching %s (verification not passed).", name)
            # Don't track a failed/terminated process.

    def _sweep_dead_pids(self):
        """Drop bookkeeping for processes that have exited, so a relaunch
        later is correctly treated as a NEW process needing a fresh decision
        (unless it's still within an active grace window)."""
        dead = [pid for pid, app in self.tracked.items() if not app.is_still_running()]
        for pid in dead:
            del self.tracked[pid]

    def run(self):
        self.logger.info("Monitor started.")
        self.logger.info("Watching locked apps: %s", list(LOCKED_APPS.keys()))

        while not self.shutdown_event.is_set():
            try:
                for proc in psutil.process_iter(["pid", "name", "exe"]):
                    if self.shutdown_event.is_set():
                        break
                    try:
                        pid = proc.info["pid"]
                        name = (proc.info["name"] or "").lower()
                        if not name:
                            continue

                        # Already tracked and still the SAME pid -> the
                        # "still open, don't re-MFA" rule. Nothing to do.
                        if pid in self.tracked:
                            continue

                        exe_path = proc.info["exe"] or ""
                        self._handle_new_process(name, pid, exe_path)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    except Exception:
                        self.logger.exception("Error handling a process")

                self._sweep_dead_pids()

            except Exception:
                self.logger.exception("Error during process scan")

            self.shutdown_event.wait(POLL_INTERVAL)

        self.logger.info("Monitor stopped.")


# =============================
# ENTRY POINT
# =============================
def main():
    log = setup_logging()
    os.makedirs(APPDATA_DIR, exist_ok=True)

    shutdown_event = threading.Event()

    def request_shutdown(*_):
        if not shutdown_event.is_set():
            log.info("Shutdown requested (signal/Ctrl+C). Stopping...")
            shutdown_event.set()
            try:
                webview.destroy_window  # no-op reference, just touch attr
            except Exception:
                pass
            # Destroy all webview windows so webview.start()'s blocking
            # loop actually returns instead of hanging forever.
            try:
                for w in list(webview.windows):
                    try:
                        w.destroy()
                    except Exception:
                        pass
            except Exception:
                log.exception("Error while destroying windows on shutdown")

    # SIGINT = Ctrl+C. SIGTERM = e.g. service manager / taskkill stop.
    signal.signal(signal.SIGINT, request_shutdown)
    try:
        signal.signal(signal.SIGTERM, request_shutdown)
    except Exception:
        pass  # not available on all platforms

    monitor = Monitor(shutdown_event)

    try:
        webview.create_window(
            "AppLocker (background)",
            html="<html><body style='font-family:sans-serif'>AppLocker is running.</body></html>",
            hidden=True,
        )
        # webview.start() blocks the main thread running the GUI loop, and
        # runs monitor.run in a worker thread. Ctrl+C on Windows delivers
        # SIGINT to the main thread; our handler destroys all windows so
        # this call returns instead of hanging.
        webview.start(monitor.run, debug=False)
    except KeyboardInterrupt:
        request_shutdown()
    except Exception:
        log.exception("Fatal error -- exiting.")
        shutdown_event.set()
        os._exit(1)
    finally:
        shutdown_event.set()
        log.info("Exited cleanly.")


if __name__ == "__main__":
    main()