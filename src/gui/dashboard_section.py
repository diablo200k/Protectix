from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QFrame, QGridLayout, QSizePolicy
)
from PyQt5.QtCore import Qt, QTimer, QDateTime
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette
import os
import psutil
import platform
import time
from datetime import datetime, timedelta
from utils.report_generator import ReportGenerator

class StatsCard(QFrame):
    """Widget affichant une statistique avec icône et titre."""
    
    def __init__(self, title, value, icon_text, color="#3498db"):
        super().__init__()
        self.setFrameShape(QFrame.StyledPanel)
        self.setFrameShadow(QFrame.Raised)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.setStyleSheet(f"""
            StatsCard {{
                background-color: white;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
            }}
        """)
        
        # Layout principal
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Icône (simplifiée en texte pour ce prototype)
        icon_label = QLabel(icon_text)
        icon_label.setStyleSheet(f"""
            font-size: 24px;
            color: {color};
            background-color: {color}25;
            border-radius: 20px;
            padding: 10px;
        """)
        icon_label.setFixedSize(50, 50)
        icon_label.setAlignment(Qt.AlignCenter)
        
        # Titre et valeur
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 14px; color: #777; margin-top: 10px;")
        
        value_label = QLabel(str(value))
        value_label.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {color};")
        
        # Disposition des éléments
        layout.addWidget(icon_label, 0, Qt.AlignHCenter)
        layout.addWidget(title_label, 0, Qt.AlignHCenter)
        layout.addWidget(value_label, 0, Qt.AlignHCenter)
        layout.addStretch()

def dashboard_section_widget():
    """Crée un tableau de bord avec des statistiques clés."""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setSpacing(20)
    
    # Titre du tableau de bord
    header = QLabel("Tableau de bord SecuShield")
    header.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50; margin-bottom: 10px;")
    layout.addWidget(header)
    
    # Date et heure actuelles
    date_time = QLabel()
    date_time.setStyleSheet("font-size: 14px; color: #7f8c8d; margin-bottom: 20px;")
    layout.addWidget(date_time)
    
    # Mise à jour de l'heure toutes les secondes
    def update_datetime():
        current = QDateTime.currentDateTime()
        date_time.setText(current.toString("dddd d MMMM yyyy, hh:mm:ss"))
    
    timer = QTimer(widget)
    timer.timeout.connect(update_datetime)
    timer.start(1000)  # Mise à jour chaque seconde
    update_datetime()  # Initialisation
    
    # Widgets de statistiques dans une grille
    stats_grid = QGridLayout()
    stats_grid.setSpacing(15)
    
    # Récupérer les rapports pour les statistiques
    reports = ReportGenerator.list_reports()
    
    # Calculer le nombre total de menaces détectées
    total_threats = sum(report.get('threat_count', 0) for report in reports)
    
    # Trouver la date du dernier scan
    last_scan_date = "Jamais"
    if reports:
        try:
            # Trier les rapports par date (le premier est le plus récent)
            last_timestamp = reports[0].get('timestamp', '')
            last_scan_datetime = datetime.fromisoformat(last_timestamp)
            last_scan_date = last_scan_datetime.strftime("%d/%m/%Y %H:%M")
        except:
            pass
    
    # Récupérer les fichiers en quarantaine
    quarantine_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../data/quarantine"))
    quarantine_count = 0
    if os.path.exists(quarantine_dir):
        quarantine_count = len(os.listdir(quarantine_dir))
    
    # Ajouter les cartes de statistiques
    stats_grid.addWidget(StatsCard("Menaces détectées", total_threats, "🔍", "#e74c3c"), 0, 0)
    stats_grid.addWidget(StatsCard("En quarantaine", quarantine_count, "🔒", "#f39c12"), 0, 1)
    stats_grid.addWidget(StatsCard("Scans effectués", len(reports), "📊", "#2ecc71"), 0, 2)
    stats_grid.addWidget(StatsCard("Dernier scan", last_scan_date, "🕒", "#3498db"), 1, 0)
    
    # Calcul de l'utilisation du disque
    try:
        disk_usage = psutil.disk_usage('/')
        disk_percent = disk_usage.percent
    except:
        disk_percent = 0
    
    stats_grid.addWidget(StatsCard("Utilisation disque", f"{disk_percent}%", "💾", "#9b59b6"), 1, 1)
    stats_grid.addWidget(StatsCard("Système", platform.system(), "💻", "#34495e"), 1, 2)
    
    layout.addLayout(stats_grid)
    
    # Section des actions rapides
    quick_actions = QLabel("Actions rapides")
    quick_actions.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50; margin-top: 20px;")
    layout.addWidget(quick_actions)
    
    buttons_layout = QHBoxLayout()
    buttons_layout.setSpacing(10)
    
    # Boutons d'action rapide
    scan_btn = QPushButton("Scan rapide")
    scan_btn.setStyleSheet("""
        QPushButton {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #2980b9;
        }
    """)
    
    update_btn = QPushButton("Mise à jour")
    update_btn.setStyleSheet("""
        QPushButton {
            background-color: #2ecc71;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #27ae60;
        }
    """)
    
    quarantine_btn = QPushButton("Quarantaine")
    quarantine_btn.setStyleSheet("""
        QPushButton {
            background-color: #f39c12;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #e67e22;
        }
    """)
    
    # Ajouter les boutons au layout
    buttons_layout.addWidget(scan_btn)
    buttons_layout.addWidget(update_btn)
    buttons_layout.addWidget(quarantine_btn)
    
    layout.addLayout(buttons_layout)
    
    # Ajouter un espace en fin de layout
    layout.addStretch()
    
    # Connexion des boutons aux actions
    def on_scan_btn_clicked():
        # Ici, vous pouvez rediriger vers la section scan
        # ou déclencher directement un scan rapide
        pass
    
    def on_update_btn_clicked():
        # Déclencher une mise à jour des signatures
        pass
    
    def on_quarantine_btn_clicked():
        # Rediriger vers la section quarantaine
        pass
    
    scan_btn.clicked.connect(on_scan_btn_clicked)
    update_btn.clicked.connect(on_update_btn_clicked)
    quarantine_btn.clicked.connect(on_quarantine_btn_clicked)
    
    return widget