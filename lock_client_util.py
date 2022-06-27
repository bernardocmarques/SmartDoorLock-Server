import socket


class LockClient:

    def __init__(self, ip):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = ip

        self._open_sock()

    def _open_sock(self):
        self.sock.connect((self.ip, 3333))  # fixme hardcoded
        self.sock.settimeout(3)

    def send_msg_to_lock(self, msg):
        try:
            self.sock.send(msg.encode())

            res = self.sock.recv(1024)
        except TimeoutError as toe:
            return None

        return res

    def close_sock(self):
        self.sock.close()
