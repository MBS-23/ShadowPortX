# gui/threads/udp_scan_worker.py

import socket
import random
from PyQt6.QtCore import QRunnable, QObject, pyqtSignal

class WorkerSignals(QObject):
    result = pyqtSignal(str)
    finished = pyqtSignal()

class UdpScanWorker(QRunnable):
    def __init__(self, target, port, timeout=1.5):
        super().__init__()
        self.target = target
        self.port = port
        self.timeout = timeout
        self.signals = WorkerSignals()

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Send random UDP data
            data = bytes([random.randint(0, 255) for _ in range(8)])
            sock.sendto(data, (self.target, self.port))

            try:
                response, _ = sock.recvfrom(1024)
                # Received data → open port
                msg = f"[UDP OPEN] Port {self.port} responded."
            except socket.timeout:
                msg = f"[UDP FILTERED] Port {self.port} did not respond."
            except Exception as e:
                msg = f"[UDP ERROR] Port {self.port}: {str(e)}"
        except Exception as e:
            msg = f"[UDP ERROR] Port {self.port}: {str(e)}"
        finally:
            sock.close()

        # Emit result
        self.signals.result.emit(msg)
        self.signals.finished.emit()
