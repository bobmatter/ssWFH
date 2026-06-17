import psutil
import subprocess
import time
import threading
import hashlib
import json
import os
import webview
import requests



LockedApps=["notion.exe", "chrome.exe","ms-teams.exe","notepad.exe"]
isOpened= {
  "notion.exe": False,
  "chrome.exe": False,
  "ms-teams.exe": False,
  "notepad.exe":"False"
}


MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 30


# class App:


# =============================
# CONFIG
# =============================
APPDATA_DIR = os.path.join(os.getenv("LOCALAPPDATA"), "AppLockerrrr")


# =============================
# AdapID WINDOW
# =============================
def show_AdapID_window(app_name, exe_path):  
 Behaviour_html_URL = requests.get("https://api357.cf.adapid.link/idv/adapidDesktop/api/getHTML")
 window = webview.create_window('AdapID', Behaviour_html_URL)
 webview.start()
 isLegitimate=requests.get("https://api357.cf.adapid.link/idv/adapidDesktop/api/complete")
 if(isLegitimate):
     subprocess.Popen(exe_path)
     isOpened[app_name]=True
 else:
     return
     

def starter():
    for proc in psutil.process_iter(['name', 'exe']):
            try:
                name = proc.info['name']
                if not name:
                    continue

                if name.lower() in LockedApps and (not isOpened[name.lower()]):
                    exe_path = proc.info['exe']
                    proc.terminate()
                    show_AdapID_window(exe_path)
                    

            except:
                pass


if __name__ == "__main__":
    starter()
    
        


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
