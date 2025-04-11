from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QListWidget, QFrame, QListWidgetItem
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt, QSize
import sys

# Importer vos modules de section (à adapter selon vos besoins)
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
        
        # Feuille de style globale pour une allure moderne et élégante
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ecf0f1;
            }
            /* Conteneur de la sidebar avec dégradé et arrondis */
            QWidget#sidebarContainer {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 #2c3e50, stop:1 #34495e);
                border-top-left-radius: 10px;
                border-bottom-left-radius: 10px;
            }
            /* Style de la barre latérale */
            QListWidget {
                background: transparent;
                color: #ecf0f1;
                font-size: 16px;
                border: none;
            }
            QListWidget::item {
                padding: 15px;
                margin: 5px 10px;
                border-radius: 5px;
            }
            QListWidget::item:selected {
                background-color: rgba(255, 255, 255, 0.2);
            }
            /* Zone principale (stacked widget) */
            QStackedWidget {
                background-color: #ffffff;
                border: none;
                border-radius: 10px;
            }
        """)
        
        # Widget central et mise en page principale
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(10)
        
        # --- Création de la barre latérale ---
        # Conteneur de la sidebar avec objet nommée pour le styling
        sidebar_container = QWidget()
        sidebar_container.setObjectName("sidebarContainer")
        sidebar_layout = QVBoxLayout(sidebar_container)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(10)
        
        # Header de la barre latérale
        sidebar_header = QLabel("SecuShield")
        sidebar_header.setAlignment(Qt.AlignCenter)
        sidebar_header.setStyleSheet("font-size: 24px; color: #ffffff; font-weight: bold; padding: 20px 0;")
        sidebar_layout.addWidget(sidebar_header)
        
        # Création de la liste du menu latéral avec possibilité d'ajouter des icônes
        self.sidebar = QListWidget()
        # Exemple d'éléments avec icônes (décommentez la ligne setIcon si vous disposez d'icônes)
        menu_items = [
            ("Scan de fichiers", "scan_icon.png"),
            ("Quarantaine", "quarantine_icon.png"),
            ("Rapports", "reports_icon.png"),
            ("Mise à jour", "update_icon.png"),
            ("Guide de sécurité", "guide_icon.png")
        ]
        for text, icon_path in menu_items:
            item = QListWidgetItem(text)
            # Si vous disposez d'icônes, décommentez la ligne suivante :
            # item.setIcon(QIcon(icon_path))
            item.setSizeHint(QSize(180, 40))
            self.sidebar.addItem(item)
            
        self.sidebar.currentRowChanged.connect(self.display_section)
        sidebar_layout.addWidget(self.sidebar)
        sidebar_container.setFixedWidth(240)
        
        # --- Création de la zone principale ---
        self.stack = QStackedWidget()
        self.stack.addWidget(scan_section_widget())
        self.stack.addWidget(quarantine_section_widget())
        self.stack.addWidget(report_section_widget())
        self.stack.addWidget(update_section_widget())
        self.stack.addWidget(guide_section_widget())
        
        # Ajout des conteneurs à la mise en page principale
        self.main_layout.addWidget(sidebar_container)
        self.main_layout.addWidget(self.stack)
        
    def display_section(self, index):
        self.stack.setCurrentIndex(index)
        
def run_gui():
    app = QApplication(sys.argv)
    # Définir la police globale
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = SecuShieldGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    run_gui()
