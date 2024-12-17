import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import os
import hashlib
import time
import threading
import queue
import uuid
from datetime import datetime

SCAN_FOLDER = "data/to_scan"

def scan_files(main_frame):
    """
    Fonction pour scanner les fichiers et afficher les menaces.
    """
    # Scanner les fichiers et détecter les menaces
    threats = []

    for filename in os.listdir(SCAN_FOLDER):
        file_path = os.path.join(SCAN_FOLDER, filename)

        # Exemple de logique pour détecter les menaces
        if filename.endswith(".exe"):  # Exemple : les fichiers .exe sont considérés comme menaçants
            threats.append(filename)

    # Afficher les menaces détectées
    for threat in threats:
        threat_frame = tk.Frame(main_frame, bg="white")
        threat_frame.pack(fill="x", pady=5)

        threat_label = tk.Label(
            threat_frame, 
            text=threat, 
            bg="white", 
            font=("Arial", 12),
            anchor="w"
        )
        threat_label.pack(side="left", padx=10)

        # Bouton pour supprimer le fichier menaçant
        def delete_threat(file_path=file_path):
            try:
                os.remove(file_path)
                messagebox.showinfo("Suppression", "Le fichier a été supprimé.")
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de supprimer le fichier : {e}")

        delete_button = tk.Button(
            threat_frame, 
            text="Supprimer", 
            command=delete_threat, 
            bg="red", 
            fg="white", 
            font=("Arial", 10)
        )
        delete_button.pack(side="right", padx=10)

def calculate_hash(file_path):
    """
    Fonction pour calculer le hash d'un fichier.
    Cette fonction gère automatiquement les erreurs de permission et passe au fichier suivant si nécessaire.
    """
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(16384):  # Lecture avec un plus grand chunk pour améliorer la performance
                file_hash.update(chunk)
        return file_path, file_hash.hexdigest()
    except PermissionError:
        print(f"Erreur de permission pour le fichier : {file_path}. Ce fichier sera ignoré.")
        return file_path, None
    except Exception as e:
        print(f"Erreur lors du calcul du hash pour {file_path} : {str(e)}")
        return file_path, None

def scan_section(main_frame):
    """
    Fonction pour afficher la section du scan avec la barre de progression.
    """
    label = tk.Label(main_frame, text="Lancez le scan du système", bg="white", font=("Arial", 14))
    label.pack(pady=20)

    progress_frame = tk.Frame(main_frame, bg="white")
    progress_frame.pack(pady=20)

    # Créer une barre de progression
    progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=400, mode="determinate")
    progress_bar.pack(pady=10)

    # Label pour afficher le pourcentage d'analyse
    percentage_label = tk.Label(main_frame, text="0%", bg="white", font=("Arial", 12))
    percentage_label.pack(pady=5)

    # Label pour afficher le temps estimé
    time_label = tk.Label(main_frame, text="Temps estimé : 0s", bg="white", font=("Arial", 12))
    time_label.pack(pady=5)

    status_label = tk.Label(main_frame, text="Scan en cours...", bg="white", font=("Arial", 12))
    status_label.pack(pady=10)

    def start_scan():
        folder_path = filedialog.askdirectory(title="Sélectionner un dossier à scanner")
        
        if not folder_path:
            messagebox.showerror("Erreur", "Aucun dossier sélectionné.")
            return
        
        # Utilisation de os.listdir pour obtenir les fichiers à scanner
        files = os.listdir(folder_path)
        total_files = len(files)

        if total_files == 0:
            messagebox.showinfo("Scan terminé", "Aucun fichier à analyser dans le dossier.")
            return

        start_time = time.time()  # Début du calcul du temps

        def process_files_in_parallel(progress_queue):
            valid_files = 0

            # Utiliser multiprocessing pour paralléliser le traitement des fichiers sur plusieurs cœurs
            for i, filename in enumerate(files, start=1):
                file_path = os.path.join(folder_path, filename)
                file_hash = calculate_hash(file_path)
                if file_hash is not None:  # Si le fichier a été correctement traité
                    valid_files += 1

                progress_queue.put((i, total_files, filename))  # Envoyer des informations de progression

            progress_queue.put("FIN")  # Indicateur de fin de traitement
            generate_report(files, valid_files)

        # Créer une queue pour transférer les informations de progression vers le thread principal
        progress_queue = queue.Queue()

        def update_progress():
            while True:
                data = progress_queue.get()
                if data == "FIN":
                    progress_bar.stop()
                    status_label.config(text="Scan terminé !")
                    break
                i, total_files, filename = data
                progress_bar['value'] = (i / total_files) * 100
                percentage_label.config(text=f"{int((i / total_files) * 100)}%")
                
                elapsed_time = time.time() - start_time
                estimated_time = (elapsed_time / i) * (total_files - i)
                minutes, seconds = divmod(estimated_time, 60)
                time_label.config(text=f"Temps estimé : {int(minutes)}m {int(seconds)}s")
                
                status_label.config(text=f"Analyse du fichier : {filename}")
                main_frame.update_idletasks()  # Mettre à jour l'interface sans la bloquer

        # Lancer l'analyse des fichiers dans un processus séparé pour ne pas bloquer l'interface
        scan_thread = threading.Thread(target=process_files_in_parallel, args=(progress_queue,))
        scan_thread.daemon = True  # Le thread sera terminé lorsque l'application se ferme
        scan_thread.start()

        # Lancer le thread pour mettre à jour la barre de progression
        def periodic_update():
            if not progress_queue.empty():
                update_progress()
                main_frame.after(100, periodic_update)  # Mettre à jour toutes les 100ms

        # Commencer à mettre à jour périodiquement la barre de progression
        main_frame.after(100, periodic_update)

    start_button = tk.Button(main_frame, text="Démarrer le scan", command=start_scan, bg="#3498db", fg="white", font=("Arial", 12))
    start_button.pack(pady=10)

def generate_report(files, valid_files):
    """
    Fonction pour générer un rapport des fichiers analysés avec un nom unique.
    """
    # Générer un nom unique basé sur l'heure actuelle et un UUID
    unique_id = uuid.uuid4().hex  # Générer un UUID unique
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # Ajouter un timestamp
    report_filename = f"scan_report_{timestamp}_{unique_id}.txt"  # Nom du fichier rapport

    with open(report_filename, "w") as report_file:
        report_file.write(f"Scan terminé !\n")
        report_file.write(f"Nombre de fichiers analysés : {valid_files}\n")
        for file in files:
            report_file.write(f"Fichier : {file}\n")
            # Vous pouvez ajouter d'autres détails comme le hash ou l'état du fichier

    messagebox.showinfo("Rapport généré", f"Le rapport a été généré : {report_filename}")

# Créer la fenêtre principale de l'application Tkinter
root = tk.Tk()
root.title("Scanner de fichiers")
root.geometry("500x600")

main_frame = tk.Frame(root, bg="white")
main_frame.pack(fill="both", expand=True)

scan_section(main_frame)

root.mainloop()
