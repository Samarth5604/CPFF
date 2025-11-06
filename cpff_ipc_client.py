import json
import time
import win32pipe, win32file, pywintypes

PIPE_NAME = r"\\.\pipe\cpff_firewall"

def send_command(payload, timeout=3):
    start = time.time()
    while time.time() - start < timeout:
        try:
            handle = win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None,
                win32file.OPEN_EXISTING,
                0, None
            )
            win32file.WriteFile(handle, json.dumps(payload).encode("utf-8"))
            result = win32file.ReadFile(handle, 65536)[1]
            win32file.CloseHandle(handle)
            return json.loads(result.decode("utf-8"))
        except pywintypes.error as e:
            if e.winerror == 2:
                time.sleep(0.3)
                continue
            raise
        except Exception:
            time.sleep(0.3)
    return None
