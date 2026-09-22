from PyQt6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout,
    QLineEdit, QCheckBox, QPushButton, QComboBox,
    QFileDialog, QSlider
)
from PyQt6.QtCore import Qt

class SettingsTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        # Apply stylesheet to make labels green
        self.setStyleSheet("""
            QLabel.sectionTitle {
                color: green;
                font-size: 16pt;
                font-weight: bold;
            }
            QLabel.subLabel {
                color: green;
                font-weight: bold;
            }
        """)

        # Title
        title = QLabel("⚙️ ShadowPortX Settings")
        title.setObjectName("settingsTitle")
        title.setProperty("class", "sectionTitle")
        layout.addWidget(title)

        # Default Port Range
        layout.addWidget(self.make_section_label("Default Port Range"))
        port_layout = QHBoxLayout()
        self.start_port = QLineEdit()
        self.start_port.setPlaceholderText("Start Port (e.g., 1)")
        self.end_port = QLineEdit()
        self.end_port.setPlaceholderText("End Port (e.g., 65535)")
        port_layout.addWidget(self.start_port)
        port_layout.addWidget(self.end_port)
        layout.addLayout(port_layout)

        # Scan Timeout
        layout.addWidget(self.make_section_label("Scan Timeout (ms)"))
        self.timeout_input = QLineEdit()
        self.timeout_input.setPlaceholderText("Timeout in milliseconds")
        layout.addWidget(self.timeout_input)

        # Max Threads
        layout.addWidget(self.make_section_label("Max Concurrent Threads"))
        self.thread_input = QLineEdit()
        self.thread_input.setPlaceholderText("e.g., 100")
        layout.addWidget(self.thread_input)

        # Export Format
        layout.addWidget(self.make_section_label("Auto Export Formats"))
        self.export_json = QCheckBox("✔️ Export as JSON")
        self.export_pdf = QCheckBox("✔️ Export as PDF")
        layout.addWidget(self.export_json)
        layout.addWidget(self.export_pdf)

        # Theme
        layout.addWidget(self.make_section_label("UI Theme"))
        self.theme_select = QComboBox()
        self.theme_select.addItems(["Light", "Dark"])
        layout.addWidget(self.theme_select)

        # Font Size
        layout.addWidget(self.make_section_label("Font Size (8 - 24 pt)"))
        self.font_slider = QSlider(Qt.Orientation.Horizontal)
        self.font_slider.setMinimum(8)
        self.font_slider.setMaximum(24)
        self.font_slider.setValue(12)
        layout.addWidget(self.font_slider)

        # Default Export Folder
        layout.addWidget(self.make_section_label("Default Export Folder"))
        folder_layout = QHBoxLayout()
        self.export_path = QLineEdit()
        self.export_path.setPlaceholderText("Choose default save location")
        self.browse_btn = QPushButton("Browse…")
        self.browse_btn.clicked.connect(self.select_folder)
        folder_layout.addWidget(self.export_path)
        folder_layout.addWidget(self.browse_btn)
        layout.addLayout(folder_layout)

        # Buttons
        button_layout = QHBoxLayout()
        self.save_btn = QPushButton("Save Settings")
        self.reset_btn = QPushButton("Reset to Defaults")
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.reset_btn)
        layout.addLayout(button_layout)

        # Confirmation Label
        self.confirm_label = QLabel("")
        layout.addWidget(self.confirm_label)

        self.setLayout(layout)

        # Connect save button
        self.save_btn.clicked.connect(self.save_settings)
        self.reset_btn.clicked.connect(self.reset_defaults)

    def make_section_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setProperty("class", "subLabel")
        return label

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Export Folder")
        if folder:
            self.export_path.setText(folder)

    def save_settings(self):
        # For now, just show confirmation
        self.confirm_label.setText("✅ Settings saved successfully!")

    def reset_defaults(self):
        self.start_port.clear()
        self.end_port.clear()
        self.timeout_input.clear()
        self.thread_input.clear()
        self.export_json.setChecked(False)
        self.export_pdf.setChecked(False)
        self.theme_select.setCurrentIndex(0)
        self.font_slider.setValue(12)
        self.export_path.clear()
        self.confirm_label.setText("✅ Settings reset to defaults.")
