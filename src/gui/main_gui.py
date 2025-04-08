from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QListWidget
)
import sys

# Importer tes modules
from gui.scan_section import scan_section_widget
from gui.quarantine_section import quarantine_section_widget
from gui.reports_section import report_section_widget
from gui.update_section import update_section_widget
from gui.guide_section import guide_section_widget

class SecuShieldGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecuShield - Antivirus")
        self.setGeometry(100, 100, 900, 600)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QHBoxLayout(self.central_widget)

        # Barre latérale
        self.sidebar = QListWidget()
        self.sidebar.addItems([
            "Scan de fichiers",
            "Quarantaine",
            "Rapports",
            "Mise à jour",
            "Guide de sécurité"
        ])
        self.sidebar.setFixedWidth(200)
        self.sidebar.setStyleSheet("background-color: #2c3e50; color: white; font-size: 16px;")
        self.sidebar.currentRowChanged.connect(self.display_section)

        # Zone principale
        self.stack = QStackedWidget()
        self.stack.addWidget(scan_section_widget())
        self.stack.addWidget(quarantine_section_widget())
        self.stack.addWidget(report_section_widget())
        self.stack.addWidget(update_section_widget())
        self.stack.addWidget(guide_section_widget())

        self.layout.addWidget(self.sidebar)
        self.layout.addWidget(self.stack)

    def display_section(self, index):
        self.stack.setCurrentIndex(index)

def run_gui():
    app = QApplication(sys.argv)
    window = SecuShieldGUI()
    window.show()
    sys.exit(app.exec_())
