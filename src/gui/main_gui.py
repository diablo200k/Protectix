from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QListWidget, QFrame, QListWidgetItem,
    QMenuBar, QMenu, QAction  # Ajout pour le menu
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt, QSize
import sys

# Importer vos modules de section (existants)
from gui.scan_section import scan_section_widget
from gui.quarantine_section import quarantine_section_widget
from gui.reports_section import report_section_widget
from gui.update_section import update_section_widget
from gui.guide_section import guide_section_widget
from gui.full_system_scan_widget import full_system_scan_widget

# Importer les nouvelles sections (bonus)
from gui.dashboard_section import dashboard_section_widget     # Tableau de bord
from gui.stats_viewer import stats_viewer_widget              # Statistiques
from gui.theme_switcher import ThemeSwitcher                  # Gestionnaire de thèmes

class SecuShieldGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecuShield - Antivirus")
        self.setGeometry(100, 100, 1000, 700)  # Fenêtre un peu plus grande
        
        # Créer la barre de menus
        self.create_menu_bar()
        
        # Initialiser le gestionnaire de thèmes
        self.theme_switcher = ThemeSwitcher(self)
        
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
        sidebar_header = QLabel("Protectix")
        sidebar_header.setAlignment(Qt.AlignCenter)
        sidebar_header.setStyleSheet("font-size: 24px; color: #ffffff; font-weight: bold; padding: 20px 0;")
        sidebar_layout.addWidget(sidebar_header)
        
        # Création de la liste du menu latéral avec possibilité d'ajouter des icônes
        self.sidebar = QListWidget()
        # Menu items avec les nouvelles sections ajoutées
        menu_items = [
            ("Tableau de bord", "dashboard_icon.png"),     # Nouvelle section
            ("Scan de fichiers", "scan_icon.png"),
            ("Scan complet", "fullscan_icon.png"), 
            ("Quarantaine", "quarantine_icon.png"),
            ("Rapports", "reports_icon.png"),
            ("Statistiques", "stats_icon.png"),           # Nouvelle section
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
        # Ajouter les widgets dans l'ordre des items du menu
        self.stack.addWidget(dashboard_section_widget())     # Nouvelle section: Tableau de bord
        self.stack.addWidget(scan_section_widget())
        self.stack.addWidget(full_system_scan_widget())
        self.stack.addWidget(quarantine_section_widget())
        self.stack.addWidget(report_section_widget())
        self.stack.addWidget(stats_viewer_widget())          # Nouvelle section: Statistiques
        self.stack.addWidget(update_section_widget())
        self.stack.addWidget(guide_section_widget())
        
        # Ajout des conteneurs à la mise en page principale
        self.main_layout.addWidget(sidebar_container)
        self.main_layout.addWidget(self.stack)
    
    def create_menu_bar(self):
        """Crée la barre de menus de l'application."""
        menubar = self.menuBar()
        
        # Menu Fichier
        file_menu = menubar.addMenu("Fichier")
        
        # Actions du menu Fichier
        scan_action = QAction("Nouveau scan", self)
        scan_action.triggered.connect(lambda: self.sidebar.setCurrentRow(1))  # Scan de fichiers
        
        quit_action = QAction("Quitter", self)
        quit_action.triggered.connect(self.close)
        
        file_menu.addAction(scan_action)
        file_menu.addSeparator()
        file_menu.addAction(quit_action)
        
        # Menu Outils
        tools_menu = menubar.addMenu("Outils")
        
        # Actions du menu Outils
        quarantine_action = QAction("Quarantaine", self)
        quarantine_action.triggered.connect(lambda: self.sidebar.setCurrentRow(3))
        
        reports_action = QAction("Rapports", self)
        reports_action.triggered.connect(lambda: self.sidebar.setCurrentRow(4))
        
        stats_action = QAction("Statistiques", self)
        stats_action.triggered.connect(lambda: self.sidebar.setCurrentRow(5))
        
        tools_menu.addAction(quarantine_action)
        tools_menu.addAction(reports_action)
        tools_menu.addAction(stats_action)
        
        # Menu Apparence (pour le thème)
        appearance_menu = menubar.addMenu("Apparence")
        
        # Le menu Apparence est géré par le ThemeSwitcher
        # Les actions seront ajoutées automatiquement par ThemeSwitcher
        
        # Menu Aide
        help_menu = menubar.addMenu("Aide")
        
        # Actions du menu Aide
        guide_action = QAction("Guide de sécurité", self)
        guide_action.triggered.connect(lambda: self.sidebar.setCurrentRow(7))
        
        about_action = QAction("À propos", self)
        about_action.triggered.connect(self.show_about)
        
        help_menu.addAction(guide_action)
        help_menu.addAction(about_action)
    
    def show_about(self):
        """Affiche la boîte de dialogue À propos."""
        from PyQt5.QtWidgets import QMessageBox
        
        about_box = QMessageBox(self)
        about_box.setWindowTitle("À propos de SecuShield")
        about_box.setTextFormat(Qt.RichText)
        about_box.setText("""
            <h2>SecuShield Antivirus</h2>
            <p>Version 1.0</p>
            <p>Un antivirus moderne et efficace pour protéger vos données.</p>
            <p>&copy; 2024 Tous droits réservés.</p>
        """)
        about_box.setIcon(QMessageBox.Information)
        about_box.exec_()
    
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