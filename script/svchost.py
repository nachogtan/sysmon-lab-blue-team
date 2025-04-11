import os
import shutil
import subprocess
import time

original = "C:\\Windows\\System32\\cmd.exe"
fake_path = os.path.expanduser("~\\Downloads\\svchost.exe")

shutil.copyfile(original, fake_path)
print(f"[+] Fake svchost.exe created at: {fake_path}")

print(f"[+] Executing fake svchost.exe...")
proc = subprocess.Popen([fake_path], shell=False)

time.sleep(10)

proc.terminate()
print(f"[+] Fake svchost.exe terminated.")
