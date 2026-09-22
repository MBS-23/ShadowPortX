# gui/threads/scan_worker.py
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
import socket

class ScanWorkerSignals(QObject):
    result = pyqtSignal(str)
    finished = pyqtSignal()

class ScanWorker(QRunnable):
    def __init__(self, target, port, scan_type):
        super().__init__()
        self.target = target
        self.port = port
        self.scan_type = scan_type
        self.signals = ScanWorkerSignals()

    def run(self):
        try:
            if self.scan_type == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                result = sock.connect_ex((self.target, self.port))
                if result == 0:
                    self.signals.result.emit(f"[OPEN] Port {self.port}")
                sock.close()
        except Exception as e:
            self.signals.result.emit(f"[ERROR] Port {self.port}: {e}")
        finally:
            self.signals.finished.emit()
