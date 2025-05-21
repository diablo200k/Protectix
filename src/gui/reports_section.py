from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QPushButton,
    QTextBrowser, QSplitter, QMessageBox, QFileDialog, QListWidgetItem,
    QMenu, QAction, QTabWidget
)
from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QDesktopServices, QIcon
import os
import webbrowser
import shutil
from datetime import datetime

# Importer la classe ReportGenerator au lieu des fonctions simples
from utils.report_generator import ReportGenerator

class ReportSectionWidget(QWidget):
    """Widget pour afficher et gérer les rapports d'analyse."""
    
    def __init__(self):
        super().__init__()
        self.reports = []
        self.setup_ui()
        self.load_reports()
    
    def setup_ui(self):
        """Configure l'interface utilisateur."""
        layout = QVBoxLayout(self)
        
        # Titre
        title = QLabel("📄 Rapports d'analyse")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #2c3e50; margin-bottom: 15px;")
        layout.addWidget(title)
        
        # Splitter pour diviser la liste et le contenu
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)
        
        # Panneau gauche: liste des rapports
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)
        
        # Liste des rapports
        self.report_list = QListWidget()
        self.report_list.setStyleSheet("""
            QListWidget {
                font-size: 14px;
                padding: 5px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
            QListWidget::item {
                padding: 8px;
                margin: 2px;
            }
            QListWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        self.report_list.itemClicked.connect(self.display_report)
        self.report_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.report_list.customContextMenuRequested.connect(self.show_context_menu)
        left_layout.addWidget(self.report_list)
        
        # Boutons pour la gestion des rapports
        buttons_layout = QHBoxLayout()
        
        # Bouton pour rafraîchir la liste
        self.refresh_btn = QPushButton("Rafraîchir")
        self.refresh_btn.setIcon(QIcon.fromTheme("view-refresh"))
        self.refresh_btn.clicked.connect(self.load_reports)
        buttons_layout.addWidget(self.refresh_btn)
        
        # Bouton pour supprimer un rapport
        self.delete_btn = QPushButton("Supprimer")
        self.delete_btn.setIcon(QIcon.fromTheme("edit-delete"))
        self.delete_btn.clicked.connect(self.delete_report)
        buttons_layout.addWidget(self.delete_btn)
        
        # Bouton pour exporter un rapport
        self.export_btn = QPushButton("Exporter")
        self.export_btn.setIcon(QIcon.fromTheme("document-save-as"))
        self.export_btn.clicked.connect(self.export_report)
        buttons_layout.addWidget(self.export_btn)
        
        left_layout.addLayout(buttons_layout)
        
        # Panneau droit: contenu du rapport
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(10, 0, 0, 0)
        
        # Onglets pour différentes vues du rapport
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 5px;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                padding: 8px 12px;
                margin-right: 2px;
                border: 1px solid #ddd;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom-color: white;
            }
        """)
        
        # Onglet HTML
        self.html_view = QTextBrowser()
        self.html_view.setOpenExternalLinks(True)
        self.tab_widget.addTab(self.html_view, "Aperçu HTML")
        
        # Onglet Texte brut
        self.text_view = QTextBrowser()
        self.text_view.setStyleSheet("font-family: monospace;")
        self.tab_widget.addTab(self.text_view, "Texte brut")
        
        right_layout.addWidget(self.tab_widget)
        
        # Bouton pour ouvrir le rapport dans un navigateur
        self.open_browser_btn = QPushButton("Ouvrir dans le navigateur")
        self.open_browser_btn.setIcon(QIcon.fromTheme("web-browser"))
        self.open_browser_btn.clicked.connect(self.open_in_browser)
        right_layout.addWidget(self.open_browser_btn)
        
        # Ajouter les panneaux au splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        
        # Définir les tailles initiales des panneaux (30% liste, 70% contenu)
        splitter.setSizes([300, 700])
    
    def load_reports(self):
        """Charge la liste des rapports."""
        self.report_list.clear()
        self.reports = ReportGenerator.list_reports()
        
        if not self.reports:
            item = QListWidgetItem("Aucun rapport disponible")
            item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            self.report_list.addItem(item)
            self.delete_btn.setEnabled(False)
            self.export_btn.setEnabled(False)
            self.open_browser_btn.setEnabled(False)
            return
        
        self.delete_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        
        for report in self.reports:
            # Formater la date pour l'affichage
            try:
                date_obj = datetime.fromisoformat(report["timestamp"])
                date_str = date_obj.strftime("%d/%m/%Y %H:%M")
            except:
                date_str = "Date inconnue"
            
            # Créer un item avec le format "Date - Menaces détectées"
            item_text = f"{date_str} - {report['threat_count']} menace(s)"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, report["id"])  # Stocker l'ID du rapport dans les données utilisateur
            
            if report["threat_count"] > 0:
                item.setForeground(Qt.red)  # Texte rouge si des menaces ont été détectées
            
            self.report_list.addItem(item)
    
    def display_report(self, item):
        """Affiche le contenu d'un rapport sélectionné."""
        report_id = item.data(Qt.UserRole)
        if not report_id:
            return
        
        # Trouver le rapport dans la liste
        selected_report = None
        for report in self.reports:
            if report["id"] == report_id:
                selected_report = report
                break
        
        if not selected_report:
            return
        
        # Activer le bouton pour ouvrir dans le navigateur
        self.open_browser_btn.setEnabled(True)
        
        # Stocker les chemins actuels pour l'ouverture dans le navigateur
        self.current_html_path = selected_report["paths"]["html"]
        
        # Charger le contenu HTML
        try:
            with open(selected_report["paths"]["html"], 'r', encoding='utf-8') as f:
                html_content = f.read()
                self.html_view.setHtml(html_content)
        except Exception as e:
            self.html_view.setPlainText(f"Erreur lors du chargement du rapport HTML: {e}")
        
        # Charger le contenu texte
        try:
            with open(selected_report["paths"]["txt"], 'r', encoding='utf-8') as f:
                text_content = f.read()
                self.text_view.setPlainText(text_content)
        except Exception as e:
            self.text_view.setPlainText(f"Erreur lors du chargement du rapport texte: {e}")
    
    def open_in_browser(self):
        """Ouvre le rapport HTML dans le navigateur par défaut."""
        if hasattr(self, 'current_html_path') and os.path.exists(self.current_html_path):
            # Convertir le chemin en URL
            url = QUrl.fromLocalFile(self.current_html_path)
            QDesktopServices.openUrl(url)
    
    def delete_report(self):
        """Supprime le rapport sélectionné."""
        current_item = self.report_list.currentItem()
        if not current_item:
            QMessageBox.information(self, "Information", "Veuillez sélectionner un rapport à supprimer.")
            return
        
        report_id = current_item.data(Qt.UserRole)
        if not report_id:
            return
        
        # Demander confirmation
        confirm = QMessageBox.question(
            self,
            "Confirmation",
            "Êtes-vous sûr de vouloir supprimer ce rapport ?\nCette action est irréversible.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            success = ReportGenerator.delete_report(report_id)
            if success:
                QMessageBox.information(self, "Suppression", "Le rapport a été supprimé avec succès.")
                self.load_reports()  # Rafraîchir la liste
                
                # Effacer les vues
                self.html_view.setHtml("")
                self.text_view.setPlainText("")
                self.open_browser_btn.setEnabled(False)
            else:
                QMessageBox.warning(self, "Erreur", "Impossible de supprimer le rapport.")
    
    def export_report(self):
        """Exporte le rapport sélectionné vers un emplacement choisi par l'utilisateur."""
        current_item = self.report_list.currentItem()
        if not current_item:
            QMessageBox.information(self, "Information", "Veuillez sélectionner un rapport à exporter.")
            return
        
        report_id = current_item.data(Qt.UserRole)
        if not report_id:
            return
        
        # Trouver le rapport dans la liste
        selected_report = None
        for report in self.reports:
            if report["id"] == report_id:
                selected_report = report
                break
        
        if not selected_report:
            return
        
        # Déterminer le type de rapport à exporter
        export_types = {
            "HTML": {"ext": ".html", "path_key": "html"},
            "Texte": {"ext": ".txt", "path_key": "txt"},
            "JSON": {"ext": ".json", "path_key": "json"}
        }
        
        # Utiliser le type actif dans l'onglet
        tab_index = self.tab_widget.currentIndex()
        if tab_index == 0:
            export_type = "HTML"
        else:
            export_type = "Texte"
        
        # Demander le chemin de destination
        default_name = f"secushield_rapport_{report_id}{export_types[export_type]['ext']}"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Exporter le rapport",
            default_name,
            f"Fichiers {export_type} (*{export_types[export_type]['ext']})"
        )
        
        if not file_path:
            return
        
        # Copier le fichier vers la destination
        source_path = selected_report["paths"][export_types[export_type]["path_key"]]
        try:
            shutil.copy2(source_path, file_path)
            QMessageBox.information(
                self,
                "Exportation réussie",
                f"Le rapport a été exporté avec succès vers:\n{file_path}"
            )
        except Exception as e:
            QMessageBox.warning(
                self,
                "Erreur d'exportation",
                f"Impossible d'exporter le rapport: {e}"
            )
    
    def show_context_menu(self, position):
        """Affiche un menu contextuel pour la liste des rapports."""
        current_item = self.report_list.currentItem()
        if not current_item or not current_item.data(Qt.UserRole):
            return
        
        context_menu = QMenu(self)
        
        # Actions du menu
        view_action = QAction("Afficher", self)
        view_action.triggered.connect(lambda: self.display_report(current_item))
        
        delete_action = QAction("Supprimer", self)
        delete_action.triggered.connect(self.delete_report)
        
        export_action = QAction("Exporter", self)
        export_action.triggered.connect(self.export_report)
        
        browser_action = QAction("Ouvrir dans le navigateur", self)
        browser_action.triggered.connect(self.open_in_browser)
        
        # Ajouter les actions au menu
        context_menu.addAction(view_action)
        context_menu.addAction(browser_action)
        context_menu.addSeparator()
        context_menu.addAction(export_action)
        context_menu.addSeparator()
        context_menu.addAction(delete_action)
        
        # Afficher le menu
        context_menu.exec_(self.report_list.mapToGlobal(position))


# Fonction pour la compatibilité avec l'interface existante
def report_section_widget():
    """Retourne une instance du widget de rapports."""
    return ReportSectionWidget()