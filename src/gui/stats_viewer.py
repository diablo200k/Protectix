from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QComboBox, QPushButton, QFrame, QTabWidget,
    QSpacerItem, QSizePolicy
)
from PyQt5.QtCore import Qt, QDateTime, QDate
from PyQt5.QtGui import QPainter, QPen, QColor, QBrush, QFont, QPolygonF
from PyQt5.QtChart import (
    QChartView, QChart, QBarSet, QBarSeries, 
    QValueAxis, QBarCategoryAxis, QPieSeries, 
    QLineSeries, QDateTimeAxis
)
import os
import json
from datetime import datetime, timedelta
from utils.report_generator import ReportGenerator

class StatsViewerWidget(QWidget):
    """Widget pour afficher des statistiques graphiques sur les scans et menaces."""
    
    def __init__(self):
        super().__init__()
        
        # Chargement des données
        self.reports = ReportGenerator.list_reports()
        
        # Configuration de l'interface
        self.setup_ui()
        
        # Générer les graphiques
        self.generate_charts()
    
    def setup_ui(self):
        """Configure l'interface utilisateur."""
        layout = QVBoxLayout(self)
        
        # Titre
        title = QLabel("📊 Statistiques et analyses")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #2c3e50; margin-bottom: 15px;")
        layout.addWidget(title)
        
        # Options de filtrage
        filter_layout = QHBoxLayout()
        
        period_label = QLabel("Période:")
        self.period_combo = QComboBox()
        self.period_combo.addItems(["7 derniers jours", "30 derniers jours", "Année en cours", "Tout"])
        self.period_combo.currentIndexChanged.connect(self.update_charts)
        
        refresh_button = QPushButton("Actualiser")
        refresh_button.clicked.connect(self.reload_data)
        
        filter_layout.addWidget(period_label)
        filter_layout.addWidget(self.period_combo)
        filter_layout.addStretch()
        filter_layout.addWidget(refresh_button)
        
        layout.addLayout(filter_layout)
        
        # Onglets pour les différents graphiques
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
        
        # Créer les widgets pour chaque onglet
        self.threats_chart_widget = QWidget()
        self.threats_chart_layout = QVBoxLayout(self.threats_chart_widget)
        
        self.scans_chart_widget = QWidget()
        self.scans_chart_layout = QVBoxLayout(self.scans_chart_widget)
        
        self.sources_chart_widget = QWidget()
        self.sources_chart_layout = QVBoxLayout(self.sources_chart_widget)
        
        # Ajouter les onglets
        self.tab_widget.addTab(self.threats_chart_widget, "Menaces détectées")
        self.tab_widget.addTab(self.scans_chart_widget, "Activité de scan")
        self.tab_widget.addTab(self.sources_chart_widget, "Sources des menaces")
        
        layout.addWidget(self.tab_widget)
    
    def reload_data(self):
        """Recharge les données depuis les rapports."""
        self.reports = ReportGenerator.list_reports()
        self.generate_charts()
    
    def generate_charts(self):
        """Génère tous les graphiques basés sur les données disponibles."""
        # Effacer les graphiques existants
        self.clear_layouts()
        
        # Filtrer les rapports selon la période sélectionnée
        filtered_reports = self.filter_reports_by_period()
        
        if not filtered_reports:
            self.show_no_data_message()
            return
        
        # Générer les graphiques pour chaque onglet
        self.generate_threats_chart(filtered_reports)
        self.generate_scans_chart(filtered_reports)
        self.generate_sources_chart(filtered_reports)
    
    def clear_layouts(self):
        """Efface tous les widgets des layouts."""
        layouts = [
            self.threats_chart_layout,
            self.scans_chart_layout,
            self.sources_chart_layout
        ]
        
        for layout in layouts:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()
    
    def show_no_data_message(self):
        """Affiche un message quand il n'y a pas de données disponibles."""
        layouts = [
            self.threats_chart_layout,
            self.scans_chart_layout,
            self.sources_chart_layout
        ]
        
        for layout in layouts:
            label = QLabel("Aucune donnée disponible pour la période sélectionnée.")
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("font-size: 14px; color: #7f8c8d; padding: 20px;")
            layout.addWidget(label)
    
    def filter_reports_by_period(self):
        """Filtre les rapports selon la période sélectionnée."""
        period = self.period_combo.currentText()
        
        if period == "Tout":
            return self.reports
        
        now = datetime.now()
        filtered = []
        
        for report in self.reports:
            try:
                timestamp = datetime.fromisoformat(report.get("timestamp", ""))
                
                if period == "7 derniers jours":
                    if now - timestamp <= timedelta(days=7):
                        filtered.append(report)
                
                elif period == "30 derniers jours":
                    if now - timestamp <= timedelta(days=30):
                        filtered.append(report)
                
                elif period == "Année en cours":
                    if timestamp.year == now.year:
                        filtered.append(report)
            
            except:
                # Ignorer les rapports avec un format de date invalide
                pass
        
        return filtered
    
    def generate_threats_chart(self, reports):
        """Génère un graphique de l'évolution des menaces détectées."""
        # Trier les rapports par date
        sorted_reports = sorted(reports, key=lambda r: r.get("timestamp", ""))
        
        # Préparer les données pour le graphique linéaire
        line_series = QLineSeries()
        line_series.setName("Menaces détectées")
        
        dates = []
        cumulative_threats = 0
        
        for i, report in enumerate(sorted_reports):
            try:
                timestamp = datetime.fromisoformat(report.get("timestamp", ""))
                report_date = QDateTime(
                    QDate(timestamp.year, timestamp.month, timestamp.day),
                    timestamp.time()
                )
                
                # Ajouter le nombre de menaces (cumulatif ou non selon préférence)
                threat_count = report.get("threat_count", 0)
                cumulative_threats += threat_count
                
                # Option 1: Afficher le cumul des menaces
                # line_series.append(report_date.toMSecsSinceEpoch(), cumulative_threats)
                
                # Option 2: Afficher chaque rapport séparément
                line_series.append(report_date.toMSecsSinceEpoch(), threat_count)
                
                dates.append(timestamp.strftime("%d/%m/%Y"))
            except:
                # Ignorer les rapports avec un format de date invalide
                pass
        
        if not line_series.count():
            label = QLabel("Pas assez de données pour générer un graphique d'évolution des menaces.")
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("font-size: 14px; color: #7f8c8d; padding: 20px;")
            self.threats_chart_layout.addWidget(label)
            return
        
        # Créer le graphique
        chart = QChart()
        chart.addSeries(line_series)
        chart.setTitle("Évolution des menaces détectées")
        chart.setAnimationOptions(QChart.SeriesAnimations)
        
        # Axe X (dates)
        axis_x = QDateTimeAxis()
        axis_x.setFormat("dd/MM/yyyy")
        axis_x.setTitleText("Date")
        
        # Axe Y (nombre de menaces)
        axis_y = QValueAxis()
        axis_y.setLabelFormat("%d")
        axis_y.setTitleText("Nombre de menaces")
        
        chart.addAxis(axis_x, Qt.AlignBottom)
        chart.addAxis(axis_y, Qt.AlignLeft)
        
        line_series.attachAxis(axis_x)
        line_series.attachAxis(axis_y)
        
        # Configurer la vue du graphique
        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.Antialiasing)
        chart_view.setMinimumHeight(400)
        
        self.threats_chart_layout.addWidget(chart_view)
        
        # Statistiques complémentaires
        total_threats = sum(report.get("threat_count", 0) for report in reports)
        avg_threats = total_threats / len(reports) if reports else 0
        
        stats_layout = QHBoxLayout()
        
        total_label = QLabel(f"Total des menaces: {total_threats}")
        total_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #e74c3c;")
        
        avg_label = QLabel(f"Moyenne par scan: {avg_threats:.2f}")
        avg_label.setStyleSheet("font-size: 14px; color: #7f8c8d;")
        
        stats_layout.addWidget(total_label)
        stats_layout.addWidget(avg_label)
        stats_layout.addStretch()
        
        self.threats_chart_layout.addLayout(stats_layout)
    
    def generate_scans_chart(self, reports):
        """Génère un graphique de l'activité de scan."""
        # Calculer le nombre de scans par jour
        scans_by_day = {}
        
        for report in reports:
            try:
                timestamp = datetime.fromisoformat(report.get("timestamp", ""))
                date_key = timestamp.strftime("%Y-%m-%d")
                
                if date_key in scans_by_day:
                    scans_by_day[date_key] += 1
                else:
                    scans_by_day[date_key] = 1
            except:
                # Ignorer les rapports avec un format de date invalide
                pass
        
        if not scans_by_day:
            label = QLabel("Pas assez de données pour générer un graphique d'activité de scan.")
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("font-size: 14px; color: #7f8c8d; padding: 20px;")
            self.scans_chart_layout.addWidget(label)
            return
        
        # Préparer les données pour le graphique à barres
        bar_set = QBarSet("Nombre de scans")
        
        categories = []
        for date_key in sorted(scans_by_day.keys()):
            year, month, day = map(int, date_key.split('-'))
            formatted_date = datetime(year, month, day).strftime("%d/%m")
            categories.append(formatted_date)
            bar_set.append(scans_by_day[date_key])
        
        series = QBarSeries()
        series.append(bar_set)
        
        # Créer le graphique
        chart = QChart()
        chart.addSeries(series)
        chart.setTitle("Activité de scan par jour")
        chart.setAnimationOptions(QChart.SeriesAnimations)
        
        # Axe X (dates)
        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        
        # Axe Y (nombre de scans)
        axis_y = QValueAxis()
        axis_y.setLabelFormat("%d")
        axis_y.setRange(0, max(scans_by_day.values()) + 1)
        
        chart.addAxis(axis_x, Qt.AlignBottom)
        chart.addAxis(axis_y, Qt.AlignLeft)
        
        series.attachAxis(axis_x)
        series.attachAxis(axis_y)
        
        # Configurer la vue du graphique
        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.Antialiasing)
        chart_view.setMinimumHeight(400)
        
        self.scans_chart_layout.addWidget(chart_view)
        
        # Statistiques complémentaires
        total_scans = len(reports)
        avg_files_scanned = 0
        avg_scan_duration = 0
        
        for report in reports:
            # Charger les données détaillées du rapport
            report_data = self.load_report_data(report.get("id"))
            if report_data and "scan_info" in report_data:
                scan_info = report_data["scan_info"]
                avg_files_scanned += scan_info.get("files_scanned", 0)
                avg_scan_duration += scan_info.get("scan_duration", 0)
        
        if total_scans > 0:
            avg_files_scanned /= total_scans
            avg_scan_duration /= total_scans
        
        stats_layout = QHBoxLayout()
        
        total_label = QLabel(f"Total des scans: {total_scans}")
        total_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        
        files_label = QLabel(f"Fichiers par scan: {avg_files_scanned:.0f}")
        files_label.setStyleSheet("font-size: 14px; color: #7f8c8d;")
        
        duration_label = QLabel(f"Durée moyenne: {avg_scan_duration:.2f} sec")
        duration_label.setStyleSheet("font-size: 14px; color: #7f8c8d;")
        
        stats_layout.addWidget(total_label)
        stats_layout.addWidget(files_label)
        stats_layout.addWidget(duration_label)
        stats_layout.addStretch()
        
        self.scans_chart_layout.addLayout(stats_layout)
    
    def generate_sources_chart(self, reports):
        """Génère un graphique des sources de menaces."""
        # Calculer le nombre de menaces par source
        threats_by_source = {}
        
        for report in reports:
            # Charger les données détaillées du rapport
            report_data = self.load_report_data(report.get("id"))
            if not report_data or "threats" not in report_data:
                continue
            
            for threat in report_data["threats"]:
                source = threat.get("source", "Inconnue")
                if source in threats_by_source:
                    threats_by_source[source] += 1
                else:
                    threats_by_source[source] = 1
        
        if not threats_by_source:
            label = QLabel("Pas assez de données pour générer un graphique des sources de menaces.")
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("font-size: 14px; color: #7f8c8d; padding: 20px;")
            self.sources_chart_layout.addWidget(label)
            return
        
        # Préparer les données pour le graphique circulaire
        series = QPieSeries()
        series.setHoleSize(0.35)  # Créer un graphique en anneau
        
        for source, count in threats_by_source.items():
            slice = series.append(source, count)
            slice.setLabelVisible(True)
            
            # Définir les couleurs selon la source
            if source.lower() == "virustotal":
                slice.setColor(QColor("#3498db"))
            elif source.lower() == "local":
                slice.setColor(QColor("#e74c3c"))
            elif source.lower() == "virustotal_upload":
                slice.setColor(QColor("#2980b9"))
            else:
                slice.setColor(QColor("#9b59b6"))
        
        # Créer le graphique
        chart = QChart()
        chart.addSeries(series)
        chart.setTitle("Sources des menaces détectées")
        chart.setAnimationOptions(QChart.SeriesAnimations)
        chart.legend().setVisible(True)
        chart.legend().setAlignment(Qt.AlignRight)
        
        # Configurer la vue du graphique
        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.Antialiasing)
        chart_view.setMinimumHeight(400)
        
        self.sources_chart_layout.addWidget(chart_view)
        
        # Types de fichiers infectés (extension)
        infected_extensions = {}
        
        for report in reports:
            report_data = self.load_report_data(report.get("id"))
            if not report_data or "threats" not in report_data:
                continue
            
            for threat in report_data["threats"]:
                file_path = threat.get("file", "")
                if file_path:
                    _, ext = os.path.splitext(file_path)
                    ext = ext.lower() if ext else "Sans extension"
                    
                    if ext in infected_extensions:
                        infected_extensions[ext] += 1
                    else:
                        infected_extensions[ext] = 1
        
        # Afficher un tableau des extensions les plus infectées
        extensions_list = sorted(infected_extensions.items(), key=lambda x: x[1], reverse=True)
        
        extensions_label = QLabel("Types de fichiers infectés:")
        extensions_label.setStyleSheet("font-size: 14px; font-weight: bold; margin-top: 15px;")
        self.sources_chart_layout.addWidget(extensions_label)
        
        extensions_text = ", ".join([f"{ext} ({count})" for ext, count in extensions_list[:5]])
        if not extensions_text:
            extensions_text = "Aucune donnée disponible"
        
        extensions_values = QLabel(extensions_text)
        extensions_values.setStyleSheet("font-size: 14px; color: #7f8c8d;")
        self.sources_chart_layout.addWidget(extensions_values)
    
    def load_report_data(self, report_id):
        """Charge les données détaillées d'un rapport."""
        try:
            return ReportGenerator.get_report(report_id)
        except:
            return None
    
    def update_charts(self):
        """Met à jour les graphiques selon la période sélectionnée."""
        self.generate_charts()


def stats_viewer_widget():
    """Fonction pour créer le widget de visualisation des statistiques."""
    return StatsViewerWidget()