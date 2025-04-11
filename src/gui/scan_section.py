from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog,
    QMessageBox, QProgressBar, QTextEdit
)
from PyQt5.QtCore import QThread, pyqtSignal, QObject
import time
import logging
from utils.file_scanner import scan_directory as scan_folder

# Handler personnalisé pour rediriger les logs dans l'UI
class LogEmitterHandler(logging.Handler, QObject):
    log_signal = pyqtSignal(str)
    
    def __init__(self):
        QObject.__init__(self)
        logging.Handler.__init__(self)
        
    def emit(self, record):
        msg = self.format(record)
        self.log_signal.emit(msg)

# Worker pour le scan dans un thread séparé
class ScanWorker(QThread):
    # Signal d'actualisation de progression : index courant, nombre total et nom du fichier en cours
    progress_update = pyqtSignal(int, int, str)
    # Signal émis lorsque le scan est terminé avec la liste des menaces détectées
    scan_finished = pyqtSignal(list)
    
    def __init__(self, folder, parent=None):
        super().__init__(parent)
        self.folder = folder
        
    def run(self):
        # On définit une fonction de callback qui va émettre les signaux de progression
        def progress_callback(index, total, file_path):
            self.progress_update.emit(index, total, file_path)
        # Appel de la fonction de scan en fournissant le callback
        threats = scan_folder(self.folder, progress_callback=progress_callback)
        self.scan_finished.emit(threats)

# Fonction de création de la section de scan
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
    progress_bar.setMaximum(100)  # La valeur max sera mise à jour lors du scan
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

    # Ajout du LogEmitterHandler au logger "scan" pour capturer et rediriger les logs
    log_handler = LogEmitterHandler()
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    log_handler.setFormatter(formatter)
    logging.getLogger("scan").addHandler(log_handler)

    # Connexion du signal de logs au QTextEdit pour affichage en temps réel
    log_handler.log_signal.connect(lambda msg: log_text.append(msg))

    # Variable pour mémoriser le temps de départ du scan
    scan_start_time = [None]

    # Référence au worker pour que celui-ci ne soit pas nettoyé par le garbage collector
    scan_worker = None

    def select_folder():
        folder_path = QFileDialog.getExistingDirectory(widget, "Sélectionner un dossier")
        if folder_path:
            # Réinitialisation de l'UI
            progress_bar.setValue(0)
            log_text.clear()
            current_file_label.setText("Fichier en cours: N/A")
            time_label.setText("Temps estimé: N/A")
            
            # On enregistre le temps de départ
            scan_start_time[0] = time.time()
            
            nonlocal scan_worker
            scan_worker = ScanWorker(folder_path)
            scan_worker.progress_update.connect(on_progress_update)
            scan_worker.scan_finished.connect(on_scan_finished)
            scan_worker.start()

    # Mise à jour de la barre de progression et estimation du temps restant
    def on_progress_update(index, total, file_path):
        progress_bar.setMaximum(total)
        progress_bar.setValue(index)
        current_file_label.setText(f"Fichier en cours: {file_path}")

        elapsed = time.time() - scan_start_time[0]
        if index > 0:
            # Calcul de l'estimation : temps écoulé divisé par le nombre de fichiers déjà traités multiplié par le nombre de fichiers restants
            estimated_total = (elapsed / index) * total
            remaining = estimated_total - elapsed
            time_label.setText(f"Temps estimé restant: {int(remaining)} sec")
        else:
            time_label.setText("Temps estimé: Calcul en cours...")

    # Traitement à la fin du scan
    def on_scan_finished(threats):
        if threats:
            QMessageBox.warning(widget, "Menaces détectées", f"{len(threats)} menaces détectées ! Consultez les rapports.")
        else:
            QMessageBox.information(widget, "Aucune menace", "Aucune menace détectée dans le dossier scanné.")

    scan_btn.clicked.connect(select_folder)
    widget.setLayout(layout)
    return widget
