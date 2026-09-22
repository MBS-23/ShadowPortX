from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
import socket

class VersionScanSignals(QObject):
    result = pyqtSignal(str)
    finished = pyqtSignal()

class VersionScanWorker(QRunnable):
    def __init__(self, target, port):
        super().__init__()
        self.target = target
        self.port = port
        self.signals = VersionScanSignals()

    def run(self):
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((self.target, self.port))
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "No response banner"
            msg = f"[OPEN] Port {self.port}/TCP | Banner: {banner}"
            self.signals.result.emit(msg)
            sock.close()
        except Exception as e:
            pass  # Do not emit anything for closed ports
        finally:
            self.signals.finished.emit()
