#appLocker.py
#here you need to fix this  
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
# mandID WINDOW
# =============================
def show_mandID_window(app_name, exe_path):  
 Behaviour_html_URL = requests.get("https://api357.cf.mandid.link/idv/mandidDesktop/api/getHTML")
 window = webview.create_window('mandID', Behaviour_html_URL)
 webview.start()
 isLegitimate=requests.get("https://api357.cf.mandid.link/idv/mandidDesktop/api/complete")
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
                    show_mandID_window(exe_path)
                    

            except:
                pass


if __name__ == "__main__":
    starter()