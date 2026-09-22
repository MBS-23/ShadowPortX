import os 
import json
from datetime import datetime
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QPushButton,
    QLineEdit, QComboBox, QTextEdit, QHBoxLayout,
    QProgressBar, QFileDialog, QMessageBox
)
from PyQt6.QtCore import QThreadPool, Qt
from gui.threads.scan_worker import ScanWorker
from gui.threads.udp_scan_worker import UdpScanWorker
from gui.threads.stealth_scan_worker import StealthScanWorker
from gui.threads.version_scan_worker import VersionScanWorker
from report_export.pdf_reporter import export_scan_to_pdf


class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.threadpool = QThreadPool()
        self.is_scanning = False
        self.results = []
        self.scan_start_time = None
        self.scan_end_time = None

        # Title
        title = QLabel("\ud83d\udd39 ShadowPortX – Offensive & Defensive Port Scanner")
        title.setObjectName("TitleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Target input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP address or domain")

        # Scan type dropdown
        self.scan_type = QComboBox()
        self.scan_type.addItems(["TCP", "UDP", "Stealth", "Version"])

        # Port range
        port_layout = QHBoxLayout()
        self.start_port = QLineEdit()
        self.start_port.setPlaceholderText("Start Port (default: 1)")
        self.start_port.setFixedWidth(120)
        self.end_port = QLineEdit()
        self.end_port.setPlaceholderText("End Port (default: 65535)")
        self.end_port.setFixedWidth(120)
        port_layout.addWidget(self.start_port)
        port_layout.addWidget(self.end_port)

        # Buttons
        self.scan_button = QPushButton("Start Scan")
        self.stop_button = QPushButton("\u23f9\ufe0f Stop Scan")
        self.export_json_btn = QPushButton("\ud83d\udcc4 Export JSON")
        self.export_pdf_btn = QPushButton("\ud83d\udcc4 Export PDF")
        self.stop_button.setEnabled(False)
        self.export_json_btn.setEnabled(False)
        self.export_pdf_btn.setEnabled(False)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)

        # Output window
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        self.result_output.setPlaceholderText("Scan results will appear here...")

        # Layout assembly
        layout.addWidget(self.target_input)
        layout.addWidget(self.scan_type)
        layout.addLayout(port_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.result_output)
        layout.addWidget(self.export_json_btn)
        layout.addWidget(self.export_pdf_btn)
        self.setLayout(layout)

        # Connect actions
        self.scan_button.clicked.connect(self.run_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.export_json_btn.clicked.connect(self.export_json)
        self.export_pdf_btn.clicked.connect(self.export_pdf)

    def run_scan(self):
        target = self.target_input.text().strip()
        scan_type = self.scan_type.currentText()
        start = self.start_port.text().strip()
        end = self.end_port.text().strip()

        if not target:
            self.result_output.append("\u26a0\ufe0f Please enter a valid target.")
            return

        try:
            start_port = int(start) if start else 1
            end_port = int(end) if end else 65535
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535) or start_port > end_port:
                raise ValueError
        except ValueError:
            self.result_output.append("\u274c Invalid port range.")
            return

        self.scan_start_time = datetime.now()
        self.result_output.clear()
        self.result_output.append(f"\ud83d\ude80 Starting {scan_type} scan on {target} (ports {start_port}-{end_port})...\n")
        self.active_workers = 0
        self.is_scanning = True
        self.results.clear()

        self.start_port_val = start_port
        self.end_port_val = end_port
        self.total_ports = end_port - start_port + 1
        self.completed_ports = 0
        self.port_queue = list(range(start_port, end_port + 1))
        self.max_concurrent_threads = 100

        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.export_json_btn.setEnabled(False)
        self.export_pdf_btn.setEnabled(False)
        self.progress_bar.setValue(0)

        def on_result(msg):
            self.results.append(msg)
            self.result_output.append(msg)

        def on_finished():
            self.active_workers -= 1
            self.completed_ports += 1
            self.update_progress()
            self.start_next_batch()
            if self.active_workers == 0 and not self.port_queue:
                self.scan_end_time = datetime.now()
                self.scan_duration = str(self.scan_end_time - self.scan_start_time)
                self.result_output.append("\n\u2705 Full scan complete.")
                self.scan_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                self.export_json_btn.setEnabled(True)
                self.export_pdf_btn.setEnabled(True)
                self.is_scanning = False

                # Auto save to Downloads
                downloads = str(Path.home() / "Downloads")
                timestamp = self.scan_start_time.strftime("%Y%m%d_%H%M%S")
                base_name = f"scan_report_{timestamp}"

                # JSON
                json_data = {
                    "target": target,
                    "scan_type": scan_type,
                    "timestamp": self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "duration": self.scan_duration,
                    "ports": []
                }
                for line in self.results:
                    try:
                        parts = line.split()
                        port = int(parts[0])
                        status = parts[-1]
                        json_data["ports"].append({"port": port, "status": status})
                    except:
                        continue
                json_path = os.path.join(downloads, base_name + ".json")
                with open(json_path, "w") as f:
                    json.dump(json_data, f, indent=4)
                self.result_output.append(f"\ud83d\udcc4 Auto-saved JSON to {json_path}")

                # PDF
                open_ports = []
                for line in self.results:
                    if "open" in line.lower():
                        try:
                            port = int(line.split()[0])
                            open_ports.append(port)
                        except:
                            continue
                pdf_data = {
                    "target": target,
                    "scan_type": scan_type,
                    "start_time": self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "open_ports": open_ports,
                    "duration": self.scan_duration
                }
                pdf_path = os.path.join(downloads, base_name + ".pdf")
                export_scan_to_pdf(pdf_data, pdf_path)
                self.result_output.append(f"\ud83d\udcc4 Auto-saved PDF to {pdf_path}")

        def launch_worker(port):
            if not self.is_scanning:
                return

            if scan_type == "UDP":
                worker = UdpScanWorker(target, port)
            elif scan_type == "Stealth":
                worker = StealthScanWorker(target, port)
            elif scan_type == "Version":
                worker = VersionScanWorker(target, port)
            else:
                worker = ScanWorker(target, port, scan_type)

            worker.signals.result.connect(on_result)
            worker.signals.finished.connect(on_finished)
            self.active_workers += 1
            self.threadpool.start(worker)

        def start_batch():
            while self.port_queue and self.active_workers < self.max_concurrent_threads:
                port = self.port_queue.pop(0)
                launch_worker(port)

        self.start_next_batch = start_batch
        self.start_next_batch()

    def update_progress(self):
        progress = int((self.completed_ports / self.total_ports) * 100)
        self.progress_bar.setValue(progress)

    def stop_scan(self):
        self.is_scanning = False
        self.port_queue.clear()
        self.result_output.append("\n\ud83d\udea9 Scan manually stopped.")
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def export_json(self):
        target = self.target_input.text().strip()
        scan_type = self.scan_type.currentText()
        timestamp = self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S") if self.scan_start_time else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration = str(self.scan_end_time - self.scan_start_time) if self.scan_start_time and self.scan_end_time else "N/A"

        port_entries = []
        for line in self.results:
            try:
                parts = line.split()
                port = int(parts[0])
                status = parts[-1]
                port_entries.append({"port": port, "status": status})
            except:
                continue

        scan_data = {
            "target": target,
            "scan_type": scan_type,
            "timestamp": timestamp,
            "duration": duration,
            "ports": port_entries
        }

        downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        os.makedirs(downloads_folder, exist_ok=True)
        default_name = f"scan_{target}_{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        filename = os.path.join(downloads_folder, default_name)

        with open(filename, "w") as f:
            json.dump(scan_data, f, indent=4)

        self.result_output.append(f"✅ JSON report saved to Downloads: {filename}")

    def export_pdf(self):
        target = self.target_input.text().strip()
        scan_type = self.scan_type.currentText()
        timestamp = self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S") if self.scan_start_time else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration = str(self.scan_end_time - self.scan_start_time) if self.scan_start_time and self.scan_end_time else "N/A"

        open_ports = []
        for line in self.results:
            try:
                if "open" in line.lower():
                    port = int(line.split()[0])
                    open_ports.append(port)
            except:
                continue

        scan_data = {
            "target": target,
            "scan_type": scan_type,
            "timestamp": timestamp,
            "open_ports": open_ports,
            "duration": duration
        }

        downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        os.makedirs(downloads_folder, exist_ok=True)
        default_name = f"scan_{target}_{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        filename = os.path.join(downloads_folder, default_name)

        export_scan_to_pdf(scan_data, filename)
        self.result_output.append(f"✅ PDF report saved to Downloads: {filename}")
