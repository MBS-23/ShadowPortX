import os
import webbrowser
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTabWidget
)
from PyQt6.QtGui import QIcon
from gui.dashboard import DashboardTab
from gui.intelligence_tab import IntelligenceTab
from gui.settings_tab import SettingsTab
from utils.resource_path import resource_path


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("ShadowPortX – Hacker's Port Scanner")
        self.setGeometry(200, 100, 1100, 700)
        self.setWindowIcon(QIcon(resource_path("assets/icon.ico")))

        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)

        # 🔘 Project Info button at the top
        top_bar = QHBoxLayout()
        self.project_info_btn = QPushButton("📄 Project Info")
        self.project_info_btn.setStyleSheet(
            "padding: 6px; font-size: 14px; background-color: #2ecc71; color: white; border-radius: 6px;"
        )
        self.project_info_btn.clicked.connect(self.open_project_info_in_browser)
        top_bar.addWidget(self.project_info_btn)
        top_bar.addStretch()

        # 🧩 Tab widget setup
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.tabs.addTab(DashboardTab(), "Dashboard")
        self.tabs.addTab(IntelligenceTab(), "Intelligence")
        self.tabs.addTab(SettingsTab(), "Settings")

        # 📦 Add everything to the main layout
        main_layout.addLayout(top_bar)
        main_layout.addWidget(self.tabs)
        self.setCentralWidget(main_widget)

        # 🎨 Load theme if available
        theme_path = resource_path("gui/theme.qss")
        try:
            with open(theme_path, "r") as f:
                self.setStyleSheet(f.read())
        except FileNotFoundError:
            print("Theme not found, running without theme.")

    def open_project_info_in_browser(self):
        # ✅ Open the bundled local HTML file (offline-safe)
        html_path = resource_path("assets/project_info.html")
        file_url = f"file:///{os.path.abspath(html_path).replace(os.sep, '/')}"
        webbrowser.open(file_url)
