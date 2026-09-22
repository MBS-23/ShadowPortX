import sys
from PyQt6.QtWidgets import QApplication, QMessageBox
from gui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)

    # Load theme stylesheet with fallback
    try:
        with open("gui/theme.qss", "r") as f:
            app.setStyleSheet(f.read())
    except FileNotFoundError:
        QMessageBox.warning(None, "Warning", "theme.qss not found. Running without theme.")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

    self.setWindowIcon(QIcon("assets/icon.png"))
if __name__ == "__main__":
    main()
