"""Check generated Xray configs and the real Browser Dialer origin boundary."""
import base64
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def socks_greeting(port, methods, login=None):
    """The listener's method choice and, for a login, its RFC 1929 verdict."""
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        connection.sendall(bytes([5, len(methods), *methods]))
        choice = connection.recv(2)
        if login is None or choice != bytes([5, 2]):
            return choice, None
        user, password = (part.encode() for part in login)
        connection.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
        return choice, connection.recv(2)


def check_listener_password(binary, fixtures):
    """Xray's inbound refuses no-auth and a wrong password, and takes the session's own."""
    with tempfile.TemporaryDirectory(dir=fixtures) as directory:
        config = json.loads((fixtures / "normal.json").read_text())
        account = config["inbounds"][0]["settings"]["accounts"][0]
        assert config["inbounds"][0]["settings"]["auth"] == "password", "The Worker listener has no password"
        port = config["inbounds"][0]["port"] = free_port()
        config_path = Path(directory) / "normal.json"
        config_path.write_text(json.dumps(config))
        process = subprocess.Popen([str(binary), "run", "-config", str(config_path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, "Xray stopped before its listener opened"
                try:
                    choice, _ = socks_greeting(port, [0])
                    break
                except OSError:
                    assert time.monotonic() < deadline, "The Worker listener did not open"
                    time.sleep(0.1)
            assert choice == bytes([5, 0xFF]), f"An unauthenticated client was let in ({choice.hex()})"
            _, wrong = socks_greeting(port, [2], (account["user"], "wrong" + account["pass"][5:]))
            assert wrong is not None and wrong[1] != 0, f"A wrong password was accepted ({wrong})"
            _, verdict = socks_greeting(port, [2], (account["user"], account["pass"]))
            assert verdict == bytes([1, 0]), f"The session's own password was refused ({verdict})"
            print(f"Worker listener: no-auth {choice.hex()}, wrong password {wrong.hex()}, own password {verdict.hex()}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def main():
    binary = Path(sys.argv[1]).resolve(strict=True)
    fixtures = Path(sys.argv[2]).resolve(strict=True)
    for mode in ("normal", "fragment", "browser"):
        subprocess.run([str(binary), "run", "-test", "-config", str(fixtures / f"{mode}.json")], check=True, capture_output=True)
    check_listener_password(binary, fixtures)
    with tempfile.TemporaryDirectory(dir=fixtures) as directory:
        config = json.loads((fixtures / "browser.json").read_text())
        config["inbounds"][0]["port"] = free_port()
        config_path = Path(directory) / "browser.json"
        config_path.write_text(json.dumps(config))
        port = free_port()
        origin = f"http://127.0.0.1:{port}"
        environment = dict(os.environ, **{"xray.browser.dialer": f"127.0.0.1:{port}"})
        process = subprocess.Popen([str(binary), "run", "-config", str(config_path)], env=environment,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, "Xray stopped before its dialer became ready"
                try:
                    request = urllib.request.Request(origin + "/", headers={"Origin": "https://unrelated.example"})
                    with urllib.request.urlopen(request, timeout=1) as response:
                        assert response.headers.get("Access-Control-Allow-Origin") == origin, "The dialer token is exposed through wildcard CORS"
                        page = response.read().decode()
                    break
                except (OSError, TimeoutError):
                    assert time.monotonic() < deadline, "The Browser Dialer did not open"
                    time.sleep(0.1)
            token = re.search(r"/websocket\?token=([a-z0-9-]+)", page).group(1)

            def upgrade(request_origin, supplied_token):
                key = base64.b64encode(os.urandom(16)).decode()
                request = (f"GET /websocket?token={supplied_token} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                           f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                           f"Sec-WebSocket-Version: 13\r\nOrigin: {request_origin}\r\n\r\n")
                with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                    connection.sendall(request.encode())
                    return connection.recv(4096).split(b"\r\n", 1)[0]

            assert b" 403 " in upgrade("https://unrelated.example", token), "A foreign webpage can join the browser bridge"
            assert b" 101 " not in upgrade(origin, "wrong-token"), "The bridge accepted an invalid token"
            assert b" 101 " in upgrade(origin, token), "The app's own browser page cannot join the bridge"
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    print("Worker engine: all three configurations and Browser Dialer origin/token checks passed")


if __name__ == "__main__":
    main()
