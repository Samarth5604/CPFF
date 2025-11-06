import json
import time
import win32file, pywintypes

PIPE_NAME = r"\\.\pipe\cpff_firewall"

class CPFFIPCClient:
    def __init__(self):
        self.pipe_name = PIPE_NAME

    def send(self, cmd, timeout=5):
        """
        Send JSON command to daemon and read full response safely.
        Handles >64KB responses by reading until EOF.
        """
        start = time.time()
        while time.time() - start < timeout:
            try:
                handle = win32file.CreateFile(
                    self.pipe_name,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None,
                    win32file.OPEN_EXISTING,
                    0, None
                )

                # Accept either dict or string command
                payload = {"cmd": cmd} if isinstance(cmd, str) else cmd
                win32file.WriteFile(handle, json.dumps(payload).encode("utf-8"))

                # --- FIX: read all chunks until done ---
                chunks = []
                while True:
                    try:
                        data = win32file.ReadFile(handle, 65536)[1]
                        if not data:
                            break
                        chunks.append(data)
                        if len(data) < 65536:
                            break
                    except pywintypes.error as e:
                        if e.winerror == 109:  # Broken pipe / EOF
                            break
                        else:
                            raise

                win32file.CloseHandle(handle)
                full_data = b"".join(chunks)
                if not full_data:
                    return None

                try:
                    return json.loads(full_data.decode("utf-8"))
                except json.JSONDecodeError as e:
                    print(f"[IPC] JSON decode error: {e}")
                    print(full_data[:300].decode('utf-8', errors='ignore') + "...")
                    return None

            except pywintypes.error as e:
                if e.winerror == 2:
                    time.sleep(0.25)
                    continue
            except Exception as e:
                print(f"[IPC Error] {e}")
                time.sleep(0.25)
        return None


# Singleton instance (used by GUI)
ipc = CPFFIPCClient()

# ✅ Backward compatibility alias for GUI calls
ipc.send_command = ipc.send
