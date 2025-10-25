"""
firewall_client.py
Reliable CLI Client for Firewall Daemon.
Includes retry logic, improved socket flushing, and a 'ping' command.
"""

import socket
import json
import sys
import argparse
import time

IPC_HOST = "127.0.0.1"
IPC_PORT = 9999
TIMEOUT = 5.0
RETRIES = 3


def send_command(cmd, debug=False):
    payload = {"cmd": cmd}
    payload_bytes = (json.dumps(payload) + "\n").encode("utf-8")

    for attempt in range(RETRIES):
        if debug:
            print(f"[CLIENT DEBUG] Attempt {attempt+1}/{RETRIES}: connecting to {IPC_HOST}:{IPC_PORT}")
        try:
            with socket.create_connection((IPC_HOST, IPC_PORT), timeout=TIMEOUT) as sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if debug:
                    print(f"[CLIENT DEBUG] Sending payload bytes: {payload_bytes!r}")

                sock.sendall(payload_bytes)
                sock.shutdown(socket.SHUT_WR)
                time.sleep(0.05)

                data = b""
                start = time.time()
                while time.time() - start < TIMEOUT:
                    try:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                        if b"\n" in chunk:
                            break
                    except socket.timeout:
                        break

                if not data:
                    if debug:
                        print("[CLIENT DEBUG] No data received, retrying...")
                    continue

                if debug:
                    print(f"[CLIENT DEBUG] Received bytes: {data!r}")

                try:
                    resp = json.loads(data.decode("utf-8").strip())
                    print(json.dumps(resp, indent=4))
                    return
                except json.JSONDecodeError:
                    print("[!] Received invalid JSON response.")
                    if debug:
                        print("[CLIENT DEBUG] Raw data:", data)
                    continue

        except (ConnectionRefusedError, TimeoutError, socket.timeout):
            if attempt < RETRIES - 1:
                if debug:
                    print(f"[CLIENT DEBUG] Retry in 0.2s...")
                time.sleep(0.2)
                continue
            print("[!] Error: Timed out waiting for response.")
            return
        except Exception as e:
            print(f"[!] Communication error: {e}")
            if debug:
                import traceback
                traceback.print_exc()
            return

    print("[!] Failed to communicate with the daemon after all retries.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["ping", "status", "reload", "shutdown"], help="Command to send to daemon")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    print(f"[*] Sending '{args.command}' command to firewall daemon...")
    send_command(args.command, debug=args.debug)


if __name__ == "__main__":
    main()
