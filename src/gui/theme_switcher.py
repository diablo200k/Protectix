from PyQt5.QtWidgets import QAction, QMenu
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt

class ThemeSwitcher:
    """Classe pour gérer le changement de thème de l'application."""
    
    def __init__(self, main_window):
        """
        Initialise le gestionnaire de thèmes.
        
        Args:
            main_window: L'instance de la fenêtre principale de l'application
        """
        self.main_window = main_window
        self.is_dark_mode = False
        self.setup_theme_menu()
    
    def setup_theme_menu(self):
        """Ajoute un menu pour le changement de thème."""
        # Créer le menu des thèmes
        self.theme_menu = QMenu("Thème", self.main_window)
        
        # Action pour le thème clair
        self.light_action = QAction("Thème clair", self.main_window)
        self.light_action.setCheckable(True)
        self.light_action.setChecked(True)
        self.light_action.triggered.connect(lambda: self.switch_theme(False))
        
        # Action pour le thème sombre
        self.dark_action = QAction("Thème sombre", self.main_window)
        self.dark_action.setCheckable(True)
        self.dark_action.triggered.connect(lambda: self.switch_theme(True))
        
        # Ajouter les actions au menu
        self.theme_menu.addAction(self.light_action)
        self.theme_menu.addAction(self.dark_action)
        
        # Ajouter le menu à la barre de menus
        # Si la fenêtre principale n'a pas de barre de menus, créez-en une d'abord
        if not hasattr(self.main_window, 'menuBar'):
            # Vous devrez ajouter manuellement le menu au layout approprié
            pass
        else:
            self.main_window.menuBar().addMenu(self.theme_menu)
    
    def switch_theme(self, dark_mode=False):
        """
        Change le thème de l'application.
        
        Args:
            dark_mode (bool): True pour le thème sombre, False pour le thème clair
        """
        self.is_dark_mode = dark_mode
        
        # Mettre à jour l'état des actions de menu
        self.dark_action.setChecked(dark_mode)
        self.light_action.setChecked(not dark_mode)
        
        # Configurer la palette de couleurs
        palette = QPalette()
        
        if dark_mode:
            # Configurer le thème sombre
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(35, 35, 35))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, QColor(25, 25, 25))
            palette.setColor(QPalette.ToolTipText, Qt.white)
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            palette.setColor(QPalette.BrightText, Qt.red)
            palette.setColor(QPalette.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.HighlightedText, Qt.black)
            
            # Style spécifique pour les widgets
            self.main_window.setStyleSheet("""
                QMainWindow {
                    background-color: #303030;
                }
                QWidget#sidebarContainer {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 #1a1a1a, stop:1 #2c2c2c);
                    border-top-left-radius: 10px;
                    border-bottom-left-radius: 10px;
                }
                QListWidget {
                    background: transparent;
                    color: white;
                    border: none;
                }
                QListWidget::item:selected {
                    background-color: rgba(42, 130, 218, 0.7);
                }
                QLabel {
                    color: white;
                }
                QPushButton {
                    background-color: #454545;
                    color: white;
                    border: none;
                    padding: 5px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #656565;
                }
                QProgressBar {
                    background-color: #353535;
                    border: 1px solid #555;
                    border-radius: 3px;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #3498db;
                    width: 10px;
                    margin: 0.5px;
                }
                QStackedWidget {
                    background-color: #252525;
                }
                QTextEdit, QListView {
                    background-color: #252525;
                    color: white;
                    border: 1px solid #454545;
                }
                QGroupBox {
                    border: 1px solid #505050;
                    border-radius: 5px;
                    margin-top: 10px;
                    color: white;
                }
                QComboBox {
                    background-color: #353535;
                    color: white;
                    border: 1px solid #555;
                    padding: 3px;
                }
                QComboBox QAbstractItemView {
                    background-color: #353535;
                    color: white;
                }
                QTabWidget::pane {
                    border: 1px solid #454545;
                }
                QTabBar::tab {
                    background-color: #353535;
                    color: white;
                    padding: 5px 10px;
                    margin-right: 2px;
                }
                QTabBar::tab:selected {
                    background-color: #656565;
                }
            """)
        else:
            # Configurer le thème clair (par défaut)
            palette = QPalette()  # Réinitialiser avec la palette par défaut
            
            # Supprimer les styles personnalisés
            self.main_window.setStyleSheet("""
                QMainWindow {
                    background-color: #ecf0f1;
                }
                QWidget#sidebarContainer {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 #2c3e50, stop:1 #34495e);
                    border-top-left-radius: 10px;
                    border-bottom-left-radius: 10px;
                }
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
                QStackedWidget {
                    background-color: #ffffff;
                    border: none;
                    border-radius: 10px;
                }
            """)
        
        # Appliquer la palette à l'application
        self.main_window.setPalette(palette)