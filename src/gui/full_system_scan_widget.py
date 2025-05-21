from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QMessageBox, QProgressBar, QTextEdit, QCheckBox,
    QComboBox, QGroupBox, QFileDialog, QRadioButton, QSpinBox
)
from PyQt5.QtGui import QTextCursor, QFont
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer, QMutex
import os
import hashlib
import requests
import time
import psutil
import concurrent.futures
from queue import Queue, Empty
# Importer le générateur de rapports
from utils.report_generator import ReportGenerator

# Clé API VirusTotal
VIRUSTOTAL_API_KEY = "77109c720de712d2c8428753f150ee82a13eac1b4f1a050c8c71605a83d20a80"
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

# Liste d'extensions potentiellement dangereuses
RISKY_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.py', 
    '.com', '.scr', '.msi', '.pif', '.hta', '.cpl', '.reg', '.vbe', '.jse',
    '.wsf', '.wsh', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2', '.lnk',
    '.inf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf'
}

# Taille maximale de fichier à scanner par défaut (en Mo)
DEFAULT_MAX_FILE_SIZE = 50

class VirusTotalScanner(QThread):
    file_scanned = pyqtSignal(str, bool)
    progress_update = pyqtSignal(int, int, str)
    finished_scanning = pyqtSignal()

    def __init__(self, files_list, max_workers=10, max_file_size=DEFAULT_MAX_FILE_SIZE, 
                 scan_only_risky=True, batch_mode=True):
        super().__init__()
        self.files_list = files_list
        self.max_workers = max_workers
        self.max_file_size = max_file_size * 1024 * 1024  # Convertir en octets
        self.scan_only_risky = scan_only_risky
        self.batch_mode = batch_mode
        self._running = True
        self.threats = []  # Pour stocker les menaces détectées
        self.scanned_count = 0
        self.total_files = len(files_list)
        self.mutex = QMutex()  # Pour sécuriser les opérations sur les variables partagées
        self.results_queue = Queue()  # Pour stocker les résultats des threads

    def run(self):
        if self.batch_mode:
            self.batch_scan()
        else:
            self.sequential_scan()
        
        # Traiter les derniers résultats dans la queue
        self.process_queue()
        
        self.finished_scanning.emit()

    def sequential_scan(self):
        """Méthode de scan séquentiel (l'originale, plus lente)."""
        for path in self.files_list:
            if not self._running:
                break
            infected = False
            
            # Vérifier la taille du fichier
            try:
                if os.path.getsize(path) > self.max_file_size:
                    self.scanned_count += 1
                    self.progress_update.emit(self.scanned_count, self.total_files, path)
                    self.file_scanned.emit(path, False)
                    continue
            except Exception:
                # Si on ne peut pas vérifier la taille, on continue
                pass
            
            # Vérifier l'extension si l'option est activée
            if self.scan_only_risky:
                _, ext = os.path.splitext(path)
                if ext.lower() not in RISKY_EXTENSIONS:
                    self.scanned_count += 1
                    self.progress_update.emit(self.scanned_count, self.total_files, path)
                    self.file_scanned.emit(path, False)
                    continue
            
            try:
                sha256 = self.compute_hash(path)
            except Exception:
                self.scanned_count += 1
                self.progress_update.emit(self.scanned_count, self.total_files, path)
                self.file_scanned.emit(path, False)
                continue
            
            try:
                resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=VT_HEADERS)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    malicious_count = data.get("last_analysis_stats", {}).get("malicious", 0)
                    suspicious_count = data.get("last_analysis_stats", {}).get("suspicious", 0)
                    infected = malicious_count > 0
                    
                    # Si infecté ou suspect, ajouter aux menaces
                    if infected or suspicious_count > 0:
                        threat = {
                            "file": path,
                            "hash": sha256,
                            "source": "virustotal",
                            "malicious": malicious_count,
                            "suspicious": suspicious_count,
                            "decision": 3  # Par défaut: ignoré
                        }
                        self.threats.append(threat)
                        
                # On ne fait pas l'upload dans la version séquentielle car c'est trop lent
                # On se limite à vérifier si le hash est connu
                
                time.sleep(0.5)  # Pause pour respecter les limites de VirusTotal
            except Exception:
                infected = False
            
            self.scanned_count += 1
            self.progress_update.emit(self.scanned_count, self.total_files, path)
            self.file_scanned.emit(path, infected)

    def batch_scan(self):
        """Méthode de scan par lots avec multithreading."""
        # Initialiser le ThreadPoolExecutor pour les calculs de hash
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Soumettre les calculs de hash
            hash_futures = {}
            
            # Fonction pour vérifier si un fichier doit être scanné
            def should_scan_file(file_path):
                try:
                    # Vérifier la taille
                    if os.path.getsize(file_path) > self.max_file_size:
                        return False
                    
                    # Vérifier l'extension
                    if self.scan_only_risky:
                        _, ext = os.path.splitext(file_path)
                        if ext.lower() not in RISKY_EXTENSIONS:
                            return False
                    
                    return True
                except:
                    return False
            
            # Filtrer les fichiers à scanner
            files_to_scan = [f for f in self.files_list if should_scan_file(f)]
            
            # Mettre à jour le total
            self.total_files = len(files_to_scan)
            
            # Calculer les hashs en parallèle
            batch_size = min(100, self.max_workers * 5)  # Taille de lot optimale
            
            for i in range(0, len(files_to_scan), batch_size):
                if not self._running:
                    break
                
                # Prendre un lot de fichiers
                batch = files_to_scan[i:i+batch_size]
                
                # Calculer les hashs en parallèle
                futures = {executor.submit(self.compute_hash_safe, path): path for path in batch}
                
                # Collecter les hashs calculés
                hashes = {}
                for future in concurrent.futures.as_completed(futures):
                    path = futures[future]
                    try:
                        hash_value = future.result()
                        if hash_value:
                            hashes[path] = hash_value
                    except Exception:
                        pass
                    
                    # Mise à jour de la progression
                    self.scanned_count += 1
                    file_path = futures[future]
                    self.progress_update.emit(self.scanned_count, self.total_files, file_path)
                
                # Si on n'a aucun hash valide, passer au lot suivant
                if not hashes:
                    continue
                
                # Préparer la requête API par lots (si possible)
                try:
                    # Option avancée: vérifier plusieurs hashes à la fois
                    # Note: cela ne fonctionne qu'avec certains abonnements VirusTotal
                    # Commentez cette section si vous avez une clé API gratuite
                    """
                    batch_url = "https://www.virustotal.com/api/v3/files"
                    params = {"hashes": ",".join(list(hashes.values())[:25])}
                    response = requests.get(batch_url, headers=VT_HEADERS, params=params)
                    """
                    
                    # Version compatible avec API gratuite: vérifier un par un
                    for path, hash_value in hashes.items():
                        if not self._running:
                            break
                        
                        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
                        response = requests.get(url, headers=VT_HEADERS)
                        
                        if response.status_code == 200:
                            data = response.json().get("data", {}).get("attributes", {})
                            malicious_count = data.get("last_analysis_stats", {}).get("malicious", 0)
                            suspicious_count = data.get("last_analysis_stats", {}).get("suspicious", 0)
                            infected = malicious_count > 0
                            
                            if infected or suspicious_count > 0:
                                # Mettre dans la queue pour traitement
                                self.results_queue.put({
                                    "path": path,
                                    "hash": hash_value,
                                    "infected": infected,
                                    "malicious": malicious_count,
                                    "suspicious": suspicious_count
                                })
                            
                            # Émettre le signal pour mise à jour de l'interface
                            self.file_scanned.emit(path, infected)
                        
                        time.sleep(0.5)  # Respecter les limites de l'API
                        
                        # Traiter les résultats accumulés dans la queue
                        self.process_queue()
                        
                except Exception as e:
                    print(f"Erreur lors de la vérification batch: {e}")

    def process_queue(self):
        """Traite les résultats dans la queue."""
        # Récupérer tous les résultats disponibles dans la queue
        while not self.results_queue.empty():
            try:
                result = self.results_queue.get(block=False)
                
                # Ajouter aux menaces
                if result.get("infected") or result.get("suspicious", 0) > 0:
                    threat = {
                        "file": result["path"],
                        "hash": result["hash"],
                        "source": "virustotal",
                        "malicious": result.get("malicious", 0),
                        "suspicious": result.get("suspicious", 0),
                        "decision": 3  # Par défaut: ignoré
                    }
                    
                    # Verrouiller pour la manipulation de la liste partagée
                    self.mutex.lock()
                    self.threats.append(threat)
                    self.mutex.unlock()
            except Empty:
                break
            except Exception as e:
                print(f"Erreur lors du traitement des résultats: {e}")

    def compute_hash_safe(self, path):
        """Calcule le hash SHA-256 d'un fichier avec gestion des erreurs."""
        try:
            return self.compute_hash(path)
        except Exception:
            return None

    def compute_hash(self, path):
        """Calcule le hash SHA-256 d'un fichier."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            chunk_size = 8192  # 8KB par chunk
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def stop(self):
        """Arrête le scanner."""
        self._running = False


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

    # Configuration du scan
    options_group = QGroupBox("Options de scan")
    options_layout = QVBoxLayout(options_group)
    
    # Emplacement à scanner
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

    # Options avancées
    advanced_layout = QHBoxLayout()
    
    # Première colonne: options basiques
    basic_options_layout = QVBoxLayout()
    
    # Scan récursif
    recursive_cb = QCheckBox("Scan récursif")
    recursive_cb.setChecked(True)
    basic_options_layout.addWidget(recursive_cb)
    
    # Scanner seulement les fichiers dangereux
    risky_files_cb = QCheckBox("Scanner uniquement les extensions potentiellement dangereuses")
    risky_files_cb.setChecked(True)
    risky_files_cb.setToolTip("Limite le scan aux fichiers exécutables, scripts et documents")
    basic_options_layout.addWidget(risky_files_cb)
    
    # Mode de scan optimisé
    optimized_mode_cb = QCheckBox("Mode de scan optimisé (plus rapide)")
    optimized_mode_cb.setChecked(True)
    optimized_mode_cb.setToolTip("Utilise le multithreading et des optimisations pour un scan plus rapide")
    basic_options_layout.addWidget(optimized_mode_cb)
    
    advanced_layout.addLayout(basic_options_layout)
    
    # Seconde colonne: réglages avancés
    advanced_options_layout = QVBoxLayout()
    
    # Taille maximale des fichiers
    size_layout = QHBoxLayout()
    size_label = QLabel("Taille max. des fichiers (Mo):")
    size_spin = QSpinBox()
    size_spin.setRange(1, 1000)
    size_spin.setValue(DEFAULT_MAX_FILE_SIZE)
    size_spin.setToolTip("Les fichiers plus grands seront ignorés")
    size_layout.addWidget(size_label)
    size_layout.addWidget(size_spin)
    advanced_options_layout.addLayout(size_layout)
    
    # Parallélisme
    threads_layout = QHBoxLayout()
    threads_label = QLabel("Threads de scan:")
    threads_spin = QSpinBox()
    threads_spin.setRange(1, os.cpu_count() or 4)
    threads_spin.setValue(min(4, os.cpu_count() or 4))
    threads_spin.setToolTip("Plus de threads = plus rapide mais plus de ressources CPU")
    threads_layout.addWidget(threads_label)
    threads_layout.addWidget(threads_spin)
    advanced_options_layout.addLayout(threads_layout)
    
    advanced_layout.addLayout(advanced_options_layout)
    options_layout.addLayout(advanced_layout)
    
    # Ajouter les options au layout
    layout.addWidget(options_group)

    # Statistiques du scan
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

    # Barre de progression
    progress_layout = QVBoxLayout()
    progress_bar = QProgressBar()
    progress_bar.setVisible(False)
    progress_layout.addWidget(progress_bar)
    
    # Label pour le fichier en cours
    current_file_label = QLabel("Fichier en cours: n/a")
    current_file_label.setWordWrap(True)
    progress_layout.addWidget(current_file_label)
    
    layout.addLayout(progress_layout)

    # Zone de log
    log_output = QTextEdit()
    log_output.setReadOnly(True)
    log_output.setFont(QFont("Consolas", 9))
    log_output.setMaximumHeight(200)  # Limiter la hauteur
    layout.addWidget(log_output)

    # Boutons d'action
    btn_layout = QHBoxLayout()
    scan_btn = QPushButton("🔍 Démarrer le Scan")
    stop_btn = QPushButton("⏹ Arrêter le Scan")
    stop_btn.setEnabled(False)
    btn_layout.addWidget(scan_btn)
    btn_layout.addWidget(stop_btn)
    btn_layout.addStretch()
    layout.addLayout(btn_layout)

    # Variables globales pour le scan
    scan_start_time = 0
    files_scanned = 0
    infected_files = 0
    stats_timer = QTimer()
    widget.scanner = None
    scan_path = None

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
            # Afficher uniquement les fichiers infectés pour réduire la quantité de logs
            pass

    def on_progress_update(current, total, file_path):
        """Mise à jour de la progression."""
        progress_bar.setMaximum(total)
        progress_bar.setValue(current)
        # Mettre à jour le fichier en cours
        current_file_label.setText(f"Fichier en cours: {file_path}")
        # Calculer le pourcentage
        percentage = int((current / total) * 100) if total > 0 else 0
        status_label.setText(f"🔍 Scan en cours... {percentage}% ({current}/{total} fichiers)")

    def on_finished_scanning():
        """Fonction appelée à la fin du scan."""
        nonlocal scan_start_time, files_scanned, infected_files, scan_path
        stats_timer.stop()
        progress_bar.setVisible(False)
        scan_btn.setEnabled(True)
        stop_btn.setEnabled(False)
        
        # Calculer le temps écoulé
        elapsed = int(time.time() - scan_start_time)
        m, s = divmod(elapsed, 60)
        
        # Mettre à jour le statut
        status_label.setText(f"✅ Scan terminé - {files_scanned} fichiers scannés, {infected_files} infectés")
        
        # Créer les informations de scan pour le rapport
        scan_info = {
            "directory": scan_path,
            "files_scanned": files_scanned,
            "scan_duration": elapsed,
            "start_time": scan_start_time,
            "end_time": time.time(),
            "infected_count": infected_files
        }
        
        # Générer un rapport si des menaces ont été détectées
        if infected_files > 0 and hasattr(widget.scanner, 'threats') and widget.scanner.threats:
            report_paths = ReportGenerator.generate_report(widget.scanner.threats, scan_info)
            
            QMessageBox.warning(
                widget,
                "Scan terminé",
                f"✅ Scan terminé en {m:02d}:{s:02d}\n"
                f"{files_scanned} fichiers scannés, {infected_files} infectés.\n"
                f"Un rapport a été généré dans la section Rapports."
            )
        else:
            QMessageBox.information(
                widget,
                "Scan terminé",
                f"✅ Scan terminé en {m:02d}:{s:02d}\n"
                f"{files_scanned} fichiers scannés, aucune infection détectée."
            )

    def start_scan():
        nonlocal scan_start_time, files_scanned, infected_files, scan_path
        scan_path = path_combo.currentText().strip()
        if not os.path.exists(scan_path):
            QMessageBox.warning(widget, "Erreur", f"Le répertoire '{scan_path}' n'existe pas!")
            return
        
        # Réinitialiser les compteurs
        files_scanned = infected_files = 0
        files_scanned_label.setText("Fichiers scannés: 0")
        infected_label.setText("Fichiers infectés: 0")
        
        # Nettoyer le log et réinitialiser l'interface
        log_output.clear()
        current_file_label.setText("Fichier en cours: n/a")
        scan_start_time = time.time()
        stats_timer.start(1000)
        progress_bar.setVisible(True)
        progress_bar.setValue(0)
        scan_btn.setEnabled(False)
        stop_btn.setEnabled(True)
        
        # Collecter les fichiers à scanner
        append_log("Recherche des fichiers à scanner...\n", "#3498db")
        
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
        
        # Mettre à jour le statut
        status_label.setText(f"🔍 Scan en cours... {len(files_list)} fichiers trouvés")
        append_log(f"Nombre total de fichiers trouvés: {len(files_list)}\n", "#3498db")
        
        # Options de scan depuis l'interface
        max_file_size = size_spin.value()
        scan_only_risky = risky_files_cb.isChecked()
        optimized_mode = optimized_mode_cb.isChecked()
        max_workers = threads_spin.value()
        
        # Afficher le résumé des options
        append_log("Options de scan:\n", "#3498db")
        append_log(f"- Récursif: {'Oui' if recursive_cb.isChecked() else 'Non'}\n")
        append_log(f"- Extensions dangereuses uniquement: {'Oui' if scan_only_risky else 'Non'}\n")
        append_log(f"- Mode optimisé: {'Oui' if optimized_mode else 'Non'}\n")
        append_log(f"- Taille max. des fichiers: {max_file_size} Mo\n")
        append_log(f"- Nombre de threads: {max_workers}\n")
        append_log("\nDémarrage du scan...\n", "#2ecc71")
        
        # Instantiate and start scanner
        widget.scanner = VirusTotalScanner(
            files_list, 
            max_workers=max_workers,
            max_file_size=max_file_size,
            scan_only_risky=scan_only_risky,
            batch_mode=optimized_mode
        )
        widget.scanner.file_scanned.connect(on_file_scanned)
        widget.scanner.progress_update.connect(on_progress_update)
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
            status_label.setText("🔄 Scan arrêté par l'utilisateur")

    scan_btn.clicked.connect(start_scan)
    stop_btn.clicked.connect(stop_scan)

    widget.setLayout(layout)
    return widget
