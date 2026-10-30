#!/usr/bin/env python3
"""Disposable Paramiko SSH server *only* loaded into the CI container's /tmp.

Exercises the exact published image's WebSocket -> Paramiko SSH connection ->
shell channel -> browser stream, without exposing an SSH port outside Docker.
"""
import socket
import time
import threading
import paramiko
from pathlib import Path

HOST = "127.0.0.1"
PORT = 22222
PASSWORD = "disposable-ci-ssh-credential-2026"
HOST_KEY = paramiko.RSAKey.generate(2048)
PUBKEY = f"{HOST_KEY.get_name()} {HOST_KEY.get_base64()}\n"
Path("/tmp/ci_ssh_host.pub").write_text(PUBKEY, encoding="ascii")

class Auth(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        if username == "switchyardci" and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
    def get_allowed_auths(self, username):
        return "password"
    def check_channel_request(self, kind, channel_id):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    def check_channel_shell_request(self, channel):
        return True
    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True

def client_session(sock):
    transport = paramiko.Transport(sock)
    try:
        transport.add_server_key(HOST_KEY)
        transport.start_server(server=Auth())
        channel = transport.accept(15)
        if channel is None:
            return  # Host-key discovery or unsuccessful password authentication.
        channel.send(b"\r\nSWITCHYARD_CI_SSH_SHELL_READY\r\n")
        while transport.is_active() and not channel.closed:
            data = channel.recv(8192)
            if not data:
                break
            if b"printf SWITCHYARD_IMAGE_SSH_OK" in data:
                channel.sendall(b"\r\nSWITCHYARD_IMAGE_SSH_OK\r\n")
    except (EOFError, OSError, paramiko.SSHException):
        pass
    finally:
        transport.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))
        listener.listen(32)
        Path("/tmp/ci_ssh_ready").write_text("ready\n")
        while True:
            sock, _ = listener.accept()
            threading.Thread(target=client_session, args=(sock,), daemon=True).start()

if __name__ == "__main__":
    main()
