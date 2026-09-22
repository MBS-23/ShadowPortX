from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QHBoxLayout
)
from PyQt6.QtCore import Qt
from core.intelligence import (
    get_whois_info, get_dns_records,
    get_ssl_info
)

class IntelligenceTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()

        # Title
        title = QLabel("🔍 Intelligence Gathering")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setObjectName("TitleLabel")
        layout.addWidget(title)

        # Domain/IP Input
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain or IP (e.g., example.com)")
        layout.addWidget(self.domain_input)

        # Button Row
        btn_layout = QHBoxLayout()
        self.whois_btn = QPushButton("WHOIS + DNS")
        self.ssl_btn = QPushButton("SSL Check")
        btn_layout.addWidget(self.whois_btn)
        btn_layout.addWidget(self.ssl_btn)
        layout.addLayout(btn_layout)

        # Output Area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        self.setLayout(layout)

        # Connect buttons
        self.whois_btn.clicked.connect(self.fetch_info)
        self.ssl_btn.clicked.connect(self.fetch_ssl)

    def fetch_info(self):
        domain = self.domain_input.text().strip()
        if not domain:
            self.output.setPlainText("⚠️ Please enter a domain.")
            return

        self.output.setPlainText(f"🔎 Fetching WHOIS and DNS info for {domain}...\n")

        # WHOIS
        whois_data = get_whois_info(domain)
        if 'error' in whois_data:
            self.output.append(f"❌ WHOIS Error: {whois_data['error']}")
        else:
            self.output.append("🗂️ WHOIS Info:")
            for key, value in whois_data.items():
                self.output.append(f"• {key.capitalize()}: {value}")

        # DNS
        dns_data = get_dns_records(domain)
        self.output.append("\n🌐 DNS Records:")
        for record_type, records in dns_data.items():
            if isinstance(records, list):
                self.output.append(f"{record_type}:")
                for r in records:
                    self.output.append(f"   - {r}")
            else:
                self.output.append(f"{record_type}: {records}")

    def fetch_ssl(self):
        domain = self.domain_input.text().strip()
        if not domain:
            self.output.setPlainText("⚠️ Enter domain first.")
            return

        self.output.setPlainText(f"🔐 Checking SSL cert for {domain}:443 ...\n")
        cert_data = get_ssl_info(domain)
        if 'error' in cert_data:
            self.output.append(f"❌ SSL Error: {cert_data['error']}")
        else:
            self.output.append("🔐 SSL Certificate Info:")
            for k, v in cert_data.items():
                self.output.append(f"• {k}: {v}")
