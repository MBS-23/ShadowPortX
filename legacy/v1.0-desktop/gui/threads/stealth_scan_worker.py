from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
import socket

class StealthScanSignals(QObject):
    result = pyqtSignal(str)
    finished = pyqtSignal()

class StealthScanWorker(QRunnable):
    def __init__(self, target, port):
        super().__init__()
        self.target = target
        self.port = port
        self.signals = StealthScanSignals()

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target, self.port))
            if result == 0:
                self.signals.result.emit(f"[OPEN] Port {self.port}")
            sock.close()
        except Exception as e:
            self.signals.result.emit(f"[ERROR] Port {self.port}: {e}")
        finally:
            self.signals.finished.emit()
