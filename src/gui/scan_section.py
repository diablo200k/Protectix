# src/gui/scan_section_widget.py

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog,
    QMessageBox, QProgressBar, QTextEdit
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, Q_ARG, QEventLoop, QTimer, QMetaObject
import time
import logging

# Importer la fonction de scan depuis vos utils
from utils.file_scanner import scan_directory as scan_folder
# Importer le helper de décision (celui-ci doit être dans src/gui/decision_helper.py)
from gui.decision_helper import DecisionHelper
# Importer le générateur de rapports
from utils.report_generator import ReportGenerator

# ----------------------------------------------------------------------
# Handler personnalisé pour rediriger les logs dans l'UI
from PyQt5.QtCore import QObject
class LogEmitterHandler(logging.Handler, QObject):
    log_signal = pyqtSignal(str)
    
    def __init__(self):
        QObject.__init__(self)
        logging.Handler.__init__(self)
        
    def emit(self, record):
        msg = self.format(record)
        self.log_signal.emit(msg)

# ----------------------------------------------------------------------
# Worker pour le scan dans un thread séparé
class ScanWorker(QThread):
    progress_update = pyqtSignal(int, int, str)
    scan_finished = pyqtSignal(list)

    def __init__(self, folder: str, decision_helper, parent=None):
        super().__init__(parent)
        self.folder = folder
        self.decision_helper = decision_helper
        self.threats = []  # Pour stocker les menaces

    def run(self):
        # Callback pour mettre à jour la progression
        def progress_callback(index, total, file_path):
            self.progress_update.emit(index, total, file_path)

        # Callback de menace : on utilise un QEventLoop et le signal decisionMade
        def threat_callback(file_path, threat_source):
            decision = None
            loop = QEventLoop()

            # Lorsque le helper émet la décision, on capture le résultat et on quitte le loop
            def on_decision(dec):
                nonlocal decision
                decision = dec
                loop.quit()

            self.decision_helper.decisionMade.connect(on_decision)
            # On s'assure que l'appel se fait dans le thread du helper (UI) via un appel en file d'attente
            QMetaObject.invokeMethod(
                self.decision_helper,
                "ask_threat_decision",
                Qt.QueuedConnection,
                Q_ARG(str, file_path),
                Q_ARG(str, threat_source)
            )
            loop.exec_()
            self.decision_helper.decisionMade.disconnect(on_decision)
            return decision

        self.threats = scan_folder(self.folder, progress_callback, threat_callback)
        self.scan_finished.emit(self.threats)

# ----------------------------------------------------------------------
# Fonction de création de la section de scan pour l'interface
def scan_section_widget():
    widget = QWidget()
    layout = QVBoxLayout(widget)

    # Titre d'information
    title_label = QLabel("Analysez vos fichiers ou dossiers pour détecter les menaces.")
    title_label.setStyleSheet("font-size: 16px;")
    layout.addWidget(title_label)

    # Barre de progression
    progress_bar = QProgressBar()
    progress_bar.setMinimum(0)
    progress_bar.setMaximum(100)  # La valeur max sera ajustée lors du scan
    layout.addWidget(progress_bar)

    # Label pour afficher le temps restant estimé
    time_label = QLabel("Temps estimé: N/A")
    layout.addWidget(time_label)

    # Label pour afficher le fichier en cours d'analyse
    current_file_label = QLabel("Fichier en cours: N/A")
    layout.addWidget(current_file_label)

    # Zone d'affichage des logs
    log_text = QTextEdit()
    log_text.setReadOnly(True)
    log_text.setPlaceholderText("Logs du scan...")
    layout.addWidget(log_text)

    # Bouton pour lancer le scan
    scan_btn = QPushButton("Sélectionner un dossier à scanner")
    scan_btn.setStyleSheet("background-color: #3498db; color: white; font-size: 14px; padding: 6px 10px;")
    layout.addWidget(scan_btn)

    # Ajout du LogEmitterHandler au logger "scan" pour rediriger les logs
    log_handler = LogEmitterHandler()
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    log_handler.setFormatter(formatter)
    logging.getLogger("scan").addHandler(log_handler)
    
    # Connexion du signal de logs pour affichage en temps réel
    log_handler.log_signal.connect(lambda msg: log_text.append(msg))

    # Variable pour mémoriser le temps de départ du scan
    scan_start_time = [None]
    
    # Variable pour mémoriser le chemin scanné
    folder_path = [None]
    
    # Variable pour mémoriser le nombre total de fichiers
    total_files = [0]

    # Référence au worker pour éviter son ramassage par le garbage collector
    scan_worker = None

    def select_folder():
        nonlocal folder_path
        folder_path = QFileDialog.getExistingDirectory(widget, "Sélectionner un dossier")
        if folder_path:
            # Réinitialisation de l'UI
            progress_bar.setValue(0)
            log_text.clear()
            current_file_label.setText("Fichier en cours: N/A")
            time_label.setText("Temps estimé: N/A")
            
            # Enregistrement du temps de départ
            scan_start_time[0] = time.time()
            
            nonlocal scan_worker
            # Créer une instance de DecisionHelper dans le thread principal
            decision_helper = DecisionHelper()
            scan_worker = ScanWorker(folder_path, decision_helper)
            scan_worker.progress_update.connect(on_progress_update)
            scan_worker.scan_finished.connect(on_scan_finished)
            scan_worker.start()

    def on_progress_update(index, total, file_path):
        # Mettre à jour le nombre total de fichiers
        total_files[0] = total
        
        progress_bar.setMaximum(total)
        progress_bar.setValue(index)
        current_file_label.setText(f"Fichier en cours: {file_path}")

        elapsed = time.time() - scan_start_time[0]
        if index > 0:
            # Estimation du temps restant
            estimated_total = (elapsed / index) * total
            remaining = estimated_total - elapsed
            time_label.setText(f"Temps estimé restant: {int(remaining)} sec")
        else:
            time_label.setText("Temps estimé: Calcul en cours...")

    def on_scan_finished(threats):
        """Fonction appelée à la fin du scan."""
        scan_end_time = time.time()
        scan_duration = scan_end_time - scan_start_time[0]
        
        # Créer les informations de scan pour le rapport
        scan_info = {
            "directory": folder_path,
            "files_scanned": total_files[0],
            "scan_duration": scan_duration,
            "start_time": scan_start_time[0],
            "end_time": scan_end_time
        }
        
        if threats:
            # Générer un rapport avec les informations de scan
            report_paths = ReportGenerator.generate_report(threats, scan_info)
            
            QMessageBox.warning(
                widget, 
                "Menaces détectées",
                f"{len(threats)} menaces détectées ! Un rapport a été généré.\n"
                f"Vous pouvez consulter le rapport dans la section Rapports."
            )
        else:
            QMessageBox.information(
                widget, 
                "Aucune menace",
                "Aucune menace détectée dans le dossier scanné."
            )

    scan_btn.clicked.connect(select_folder)
    widget.setLayout(layout)
    return widget