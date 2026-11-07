import hashlib
import hmac
import os
import re
import socket

PROTOCOL_PREFIX = "TG1"


class Renderer:
    sequence: int
    ip: str
    port: int
    code: str
    socket: socket.socket

    def setup(self) -> None:
        self.sequence = 1
        self.ip = os.environ["IP"]
        self.port = int(os.getenv("PORT", "18511"))
        self.code = os.environ["CODE"]

        self.socket = socket.create_connection((self.ip, self.port))

        challenge = self._recv_line()

        if not challenge.startswith(f"{PROTOCOL_PREFIX}|CHALLENGE|"):
            raise RuntimeError(f"Unexpected authentication challenge: {challenge}")

        _header, _operation, challenge_hex = challenge.split("|")
        digest = hmac.new(
            self.code.encode(), challenge_hex.encode(), hashlib.sha256
        ).hexdigest()

        self.socket.sendall(f"{PROTOCOL_PREFIX}|AUTH|{digest}\n".encode())

        auth_response = self._recv_line()

        if auth_response != "TG1|OK":
            raise RuntimeError(f"Display authentication failed: {auth_response}")

    def tear_down(self) -> None:
        self.socket.close()

    def render(self, buffer: str) -> None:
        buffer = re.sub(r"\[/?[A-Z]+?\]", "", buffer)
        buffer_len = len(buffer.encode())

        self.socket.sendall(
            f"{PROTOCOL_PREFIX}|{self.sequence}|{buffer_len}\n{buffer}".encode()
        )
        self.sequence += 1

    def _recv_line(self) -> str:
        data = bytearray()

        while not data.endswith(b"\n"):
            if len(data) >= 1024:
                raise RuntimeError("Display returned an oversized protocol line")
            chunk = self.socket.recv(1)
            if not chunk:
                raise RuntimeError("Display closed the connection")
            data.extend(chunk)

        return data.rstrip(b"\n").decode()
