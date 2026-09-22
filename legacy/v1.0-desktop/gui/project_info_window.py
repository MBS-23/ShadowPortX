from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl
import os
from utils.resource_path import resource_path
class ProjectInfoWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("📄 Project Info")
        self.resize(1000, 700)

        layout = QVBoxLayout()
        self.setLayout(layout)

        web_view = QWebEngineView()
        
        html_path = resource_path("assets/project_info.html")
        self.webview.load(QUrl.fromLocalFile(html_path))

        layout.addWidget(web_view)
