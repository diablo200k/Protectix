import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from concurrent.futures import ThreadPoolExecutor
from utils.file_scanner import scan_directory
from utils.quarantine_manager import list_quarantine, restore_file
from utils.report_generator import generate_report, list_reports


def show_section(frame):
    """Affiche la section sélectionnée."""
    for widget in main_frame.winfo_children():
        widget.destroy()
    frame()


def scan_section():
    """Section pour scanner un dossier spécifique."""
    tk.Label(main_frame, text="Scan de Fichiers", font=("Arial", 18, "bold"), fg="#333").pack(pady=10)

    # Barre de progression
    progress = ttk.Progressbar(main_frame, orient="horizontal", length=500, mode="determinate")
    progress.pack(pady=15)

    # Label pour afficher le fichier en cours
    file_label = tk.Label(main_frame, text="Fichier en cours d'analyse : Aucun", font=("Arial", 12))
    file_label.pack(pady=5)

    # Label pour afficher les menaces détectées
    threat_label = tk.Label(main_frame, text="Menaces détectées : 0", font=("Arial", 12), fg="red")
    threat_label.pack(pady=5)

    # Bouton pour sélectionner un dossier
    tk.Button(main_frame, text="Sélectionner un dossier", command=lambda: scan_folder(progress, file_label, threat_label)).pack(pady=10)


def scan_folder(progress, file_label, threat_label):
    """Effectue un scan d'un dossier avec optimisation."""
    folder = filedialog.askdirectory()
    if folder:
        files = []
        for root, _, filenames in os.walk(folder):
            for file in filenames:
                files.append(os.path.join(root, file))

        total_files = len(files)
        if total_files == 0:
            messagebox.showinfo("Scan terminé", "Aucun fichier à analyser.")
            return

        progress["maximum"] = total_files
        threats = []

        def process_file(file_path):
            """Analyse un fichier et retourne les menaces détectées."""
            return scan_directory(file_path)

        # Multithreading pour analyser les fichiers
        with ThreadPoolExecutor() as executor:
            for i, result in enumerate(executor.map(process_file, files)):
                progress["value"] = i + 1
                progress.update()

                if result:
                    threats.extend(result)
                    threat_label.config(text=f"Menaces détectées : {len(threats)}")
                    threat_label.update()

                file_label.config(text=f"Fichier en cours d'analyse : {files[i]}")
                file_label.update()

        progress["value"] = total_files
        file_label.config(text="Scan terminé.")

        if threats:
            report_path = generate_report(threats)
            messagebox.showinfo("Scan terminé", f"Menaces détectées : {len(threats)}\nRapport : {report_path}")
        else:
            messagebox.showinfo("Scan terminé", "Aucune menace détectée.")


def full_scan_section():
    """Section pour effectuer un scan général de tout le PC."""
    tk.Label(main_frame, text="Scan Général de Tout le PC", font=("Arial", 18, "bold"), fg="#333").pack(pady=10)

    # Barre de progression
    progress = ttk.Progressbar(main_frame, orient="horizontal", length=500, mode="determinate")
    progress.pack(pady=15)

    # Label pour afficher les menaces détectées
    threat_label = tk.Label(main_frame, text="Menaces détectées : 0", font=("Arial", 12), fg="red")
    threat_label.pack(pady=5)

    # Bouton pour lancer le scan général
    tk.Button(main_frame, text="Lancer le Scan Général", command=lambda: start_full_scan(progress, threat_label)).pack(pady=10)


def start_full_scan(progress, threat_label):
    """Effectue un scan complet de toutes les partitions du PC."""
    partitions = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
    files = []

    for partition in partitions:
        for root, _, filenames in os.walk(partition):
            for file in filenames:
                files.append(os.path.join(root, file))

    total_files = len(files)
    if total_files == 0:
        messagebox.showinfo("Scan terminé", "Aucun fichier à analyser.")
        return

    progress["maximum"] = total_files
    threats = []

    def process_file(file_path):
        """Analyse un fichier et retourne les menaces détectées."""
        return scan_directory(file_path)

    with ThreadPoolExecutor() as executor:
        for i, result in enumerate(executor.map(process_file, files)):
            progress["value"] = i + 1
            progress.update()

            if result:
                threats.extend(result)
                threat_label.config(text=f"Menaces détectées : {len(threats)}")
                threat_label.update()

    progress["value"] = total_files

    if threats:
        report_path = generate_report(threats)
        messagebox.showinfo("Scan Général Terminé", f"Menaces détectées : {len(threats)}\nRapport : {report_path}")
    else:
        messagebox.showinfo("Scan Général Terminé", "Aucune menace détectée.")


def quarantine_section():
    """Section de gestion de la quarantaine."""
    tk.Label(main_frame, text="Quarantaine", font=("Arial", 18, "bold")).pack(pady=10)
    files = list_quarantine()

    if not files:
        tk.Label(main_frame, text="Aucun fichier en quarantaine.", font=("Arial", 12)).pack(pady=10)
    else:
        for file in files:
            tk.Label(main_frame, text=file, font=("Arial", 12)).pack()
        tk.Button(main_frame, text="Restaurer", command=lambda: restore_file(files[0])).pack(pady=5)


def reports_section():
    """Section de gestion des rapports."""
    tk.Label(main_frame, text="Rapports", font=("Arial", 18, "bold")).pack(pady=10)
    reports = list_reports()

    if not reports:
        tk.Label(main_frame, text="Aucun rapport disponible.", font=("Arial", 12)).pack(pady=10)
    else:
        for report in reports:
            tk.Label(main_frame, text=report, font=("Arial", 12), fg="blue", cursor="hand2").pack()


# Configuration principale de l'application
root = tk.Tk()
root.title("SecuShield Antivirus")
root.geometry("900x600")

# Barre latérale
sidebar = tk.Frame(root, width=200, bg="#f0f0f0")
sidebar.pack(side="left", fill="y")
main_frame = tk.Frame(root, bg="white")
main_frame.pack(side="right", fill="both", expand=True)

# Navigation entre les sections
sections = {
    "Scan de fichiers": scan_section,
    "Scan général": full_scan_section,
    "Quarantaine": quarantine_section,
    "Rapports": reports_section,
}

for name, command in sections.items():
    tk.Button(sidebar, text=name, command=lambda cmd=command: show_section(cmd), padx=10, pady=5, width=20, bg="#ddd", font=("Arial", 12)).pack(pady=5)

root.mainloop()
