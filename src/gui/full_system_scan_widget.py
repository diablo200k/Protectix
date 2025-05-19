from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QMessageBox, QProgressBar, QTextEdit, QCheckBox,
    QComboBox, QGroupBox, QFileDialog
)
from PyQt5.QtGui import QTextCursor, QFont
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
import os
import hashlib
import requests
import time
import psutil

# Clé API VirusTotal
VIRUSTOTAL_API_KEY = "77109c720de712d2c8428753f150ee82a13eac1b4f1a050c8c71605a83d20a80"
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

class VirusTotalScanner(QThread):
    file_scanned = pyqtSignal(str, bool)
    finished_scanning = pyqtSignal()

    def __init__(self, files_list):
        super().__init__()
        self.files_list = files_list
        self._running = True

    def run(self):
        for path in self.files_list:
            if not self._running:
                break
            infected = False
            try:
                sha256 = self.compute_hash(path)
            except Exception:
                self.file_scanned.emit(path, False)
                continue
            try:
                resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=VT_HEADERS)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    infected = data.get("last_analysis_stats", {}).get("malicious", 0) > 0
                elif resp.status_code == 404:
                    with open(path, "rb") as f:
                        files = {"file": (os.path.basename(path), f)}
                        up = requests.post(
                            "https://www.virustotal.com/api/v3/files",
                            headers=VT_HEADERS,
                            files=files
                        )
                    if up.status_code == 200:
                        analysis_id = up.json().get("data", {}).get("id")
                        time.sleep(15)
                        rep = requests.get(
                            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers=VT_HEADERS
                        )
                        stats = rep.json().get("data", {}).get("attributes", {}).get("stats", {})
                        infected = stats.get("malicious", 0) > 0
                time.sleep(15)
            except Exception:
                infected = False
            self.file_scanned.emit(path, infected)
        self.finished_scanning.emit()

    def stop(self):
        self._running = False

    @staticmethod
    def compute_hash(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()


def full_system_scan_widget():
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setSpacing(10)

    title = QLabel("Scan Antivirus Système avec VirusTotal")
    title.setStyleSheet(
        """
        font-weight: bold; 
        font-size: 18px; 
        color: #2c3e50;
        padding: 10px;
        background-color: #ecf0f1;
        border-radius: 5px;
        """
    )
    title.setAlignment(Qt.AlignCenter)
    layout.addWidget(title)

    status_label = QLabel("🔄 Prêt pour le scan")
    status_label.setWordWrap(True)
    layout.addWidget(status_label)

    options_group = QGroupBox("Options de scan")
    options_layout = QVBoxLayout(options_group)
    path_layout = QHBoxLayout()
    path_label = QLabel("Répertoire à scanner:")
    path_combo = QComboBox()
    path_combo.setEditable(True)
    browse_btn = QPushButton("Parcourir...")
    browse_btn.setMaximumWidth(100)

    def populate_paths():
        path_combo.clear()
        paths = []
        try:
            for p in psutil.disk_partitions():
                if os.path.exists(p.mountpoint):
                    paths.append(p.mountpoint)
        except:
            pass
        for p in ["C:/", "D:/"]:
            if os.path.exists(p) and p not in paths:
                paths.append(p)
        path_combo.addItems(paths)
        if paths:
            path_combo.setCurrentText(paths[0])

    populate_paths()

    def browse_directory():
        d = QFileDialog.getExistingDirectory(widget, "Sélectionner le répertoire à scanner")
        if d:
            path_combo.setCurrentText(d)

    browse_btn.clicked.connect(browse_directory)
    path_layout.addWidget(path_label)
    path_layout.addWidget(path_combo)
    path_layout.addWidget(browse_btn)
    options_layout.addLayout(path_layout)

    recursive_cb = QCheckBox("Scan récursif")
    recursive_cb.setChecked(True)
    options_layout.addWidget(recursive_cb)
    layout.addWidget(options_group)

    stats_group = QGroupBox("Statistiques du scan")
    stats_layout = QHBoxLayout(stats_group)
    files_scanned_label = QLabel("Fichiers scannés: 0")
    infected_label = QLabel("Fichiers infectés: 0")
    elapsed_label = QLabel("Temps écoulé: 00:00")
    stats_layout.addWidget(files_scanned_label)
    stats_layout.addWidget(infected_label)
    stats_layout.addWidget(elapsed_label)
    stats_layout.addStretch()
    layout.addWidget(stats_group)

    progress_bar = QProgressBar()
    progress_bar.setVisible(False)
    layout.addWidget(progress_bar)

    log_output = QTextEdit()
    log_output.setReadOnly(True)
    log_output.setFont(QFont("Consolas", 9))
    layout.addWidget(log_output)

    btn_layout = QHBoxLayout()
    scan_btn = QPushButton("🔍 Démarrer le Scan")
    stop_btn = QPushButton("⏹ Arrêter le Scan")
    stop_btn.setEnabled(False)
    btn_layout.addWidget(scan_btn)
    btn_layout.addWidget(stop_btn)
    btn_layout.addStretch()
    layout.addLayout(btn_layout)

    scan_start_time = 0
    files_scanned = 0
    infected_files = 0
    stats_timer = QTimer()
    widget.scanner = None

    def append_log(text, color="#ecf0f1"):
        log_output.moveCursor(QTextCursor.End)
        log_output.insertHtml(f'<span style="color: {color};">{text}</span>')
        log_output.moveCursor(QTextCursor.End)

    def update_stats():
        nonlocal scan_start_time
        if scan_start_time:
            elapsed = int(time.time() - scan_start_time)
            m, s = divmod(elapsed, 60)
            elapsed_label.setText(f"Temps écoulé: {m:02d}:{s:02d}")

    stats_timer.timeout.connect(update_stats)

    def on_file_scanned(path, infected):
        nonlocal files_scanned, infected_files
        files_scanned += 1
        files_scanned_label.setText(f"Fichiers scannés: {files_scanned}")
        if infected:
            infected_files += 1
            infected_label.setText(f"Fichiers infectés: {infected_files}")
            append_log(f"{path} : MALICIEUX\n", "#e74c3c")
        else:
            append_log(f"{path} : OK\n")

    def on_finished_scanning():
        nonlocal scan_start_time
        stats_timer.stop()
        progress_bar.setVisible(False)
        scan_btn.setEnabled(True)
        stop_btn.setEnabled(False)
        elapsed = int(time.time() - scan_start_time)
        m, s = divmod(elapsed, 60)
        QMessageBox.information(
            widget,
            "Scan terminé",
            f"✅ Scan terminé en {m:02d}:{s:02d}\n{files_scanned} fichiers scannés, {infected_files} infectés."
        )

    def start_scan():
        nonlocal scan_start_time, files_scanned, infected_files
        scan_path = path_combo.currentText().strip()
        if not os.path.exists(scan_path):
            QMessageBox.warning(widget, "Erreur", f"Le répertoire '{scan_path}' n'existe pas!")
            return
        files_scanned = infected_files = 0
        files_scanned_label.setText("Fichiers scannés: 0")
        infected_label.setText("Fichiers infectés: 0")
        log_output.clear()
        scan_start_time = time.time()
        stats_timer.start(1000)
        progress_bar.setVisible(True)
        scan_btn.setEnabled(False)
        stop_btn.setEnabled(True)
        # Collect files
        files_list = []
        if recursive_cb.isChecked():
            for root, dirs, files in os.walk(scan_path):
                for f in files:
                    files_list.append(os.path.join(root, f))
        else:
            for f in os.listdir(scan_path):
                p = os.path.join(scan_path, f)
                if os.path.isfile(p):
                    files_list.append(p)
        # Instantiate and start scanner
        widget.scanner = VirusTotalScanner(files_list)
        widget.scanner.file_scanned.connect(on_file_scanned)
        widget.scanner.finished_scanning.connect(on_finished_scanning)
        widget.scanner.start()

    def stop_scan():
        if widget.scanner and widget.scanner.isRunning():
            widget.scanner.stop()
            widget.scanner.wait()
            append_log("\n=== Scan arrêté par l'utilisateur ===\n", "#f39c12")
            stats_timer.stop()
            progress_bar.setVisible(False)
            scan_btn.setEnabled(True)
            stop_btn.setEnabled(False)

    scan_btn.clicked.connect(start_scan)
    stop_btn.clicked.connect(stop_scan)

    widget.setLayout(layout)
    return widget
