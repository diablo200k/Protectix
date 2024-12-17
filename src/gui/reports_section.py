import tkinter as tk
from tkinter import messagebox
import os

# Dossier contenant les rapports et les fichiers à scanner
SCAN_FOLDER = "data/to_scan"
REPORTS_FOLDER = "data/reports"

# Exemple de fichiers suspects (vous pouvez ajouter votre propre logique de détection)
SUSPECT_FILES = ["suspect1.txt", "suspect2.txt"]

def reports_section(main_frame):
    """
    Fonction pour afficher la section des rapports d'analyse.
    """
    # Titre principal
    label = tk.Label(
        main_frame, 
        text="Visualisez les rapports d'analyse précédents :", 
        bg="white", 
        font=("Arial", 14)
    )
    label.pack(pady=20)

    # Fonction pour rafraîchir la liste des rapports
    def refresh_report_list():
        """
        Rafraîchit la liste des rapports affichés.
        """
        # Supprimer les widgets existants dans la liste des rapports
        for widget in report_list_frame.winfo_children():
            widget.destroy()

        # Créer le dossier des rapports s'il n'existe pas
        if not os.path.exists(REPORTS_FOLDER):
            os.makedirs(REPORTS_FOLDER)

        # Lister les rapports disponibles
        reports = os.listdir(REPORTS_FOLDER)

        if not reports:
            # Afficher un message si aucun rapport n'est disponible
            no_reports_label = tk.Label(
                report_list_frame, 
                text="Aucun rapport disponible.", 
                bg="white", 
                font=("Arial", 12)
            )
            no_reports_label.pack(pady=5)
        else:
            # Afficher chaque rapport avec un bouton pour l'ouvrir
            for report in reports:
                # Vérifier qu'il s'agit bien d'un fichier
                report_path = os.path.join(REPORTS_FOLDER, report)
                if os.path.isfile(report_path):
                    # Ligne pour chaque rapport
                    report_frame = tk.Frame(report_list_frame, bg="white")
                    report_frame.pack(fill="x", pady=5)

                    # Nom du rapport
                    report_label = tk.Label(
                        report_frame, 
                        text=report, 
                        bg="white", 
                        font=("Arial", 12),
                        anchor="w"
                    )
                    report_label.pack(side="left", padx=10)

                    # Fonction pour ouvrir un rapport
                    def open_report(file_path=report_path):
                        """
                        Ouvre le rapport sélectionné.
                        """
                        try:
                            with open(file_path, "r", encoding="utf-8") as f:
                                content = f.read()
                            messagebox.showinfo(
                                f"Rapport : {os.path.basename(file_path)}", 
                                content
                            )
                        except Exception as e:
                            messagebox.showerror(
                                "Erreur", 
                                f"Impossible d'ouvrir le rapport : {e}"
                            )

                    # Bouton pour ouvrir le rapport
                    open_button = tk.Button(
                        report_frame, 
                        text="Ouvrir", 
                        command=open_report, 
                        bg="#3498db", 
                        fg="white", 
                        font=("Arial", 10)
                    )
                    open_button.pack(side="right", padx=10)

    # Cadre pour afficher la liste des rapports
    report_list_frame = tk.Frame(main_frame, bg="white")
    report_list_frame.pack(pady=10, fill="both", expand=True)

    # Bouton pour actualiser la liste des rapports
    refresh_button = tk.Button(
        main_frame, 
        text="Actualiser", 
        command=refresh_report_list, 
        bg="#3498db", 
        fg="white", 
        font=("Arial", 12)
    )
    refresh_button.pack(pady=10)

    # Chargement initial de la liste des rapports
    refresh_report_list()

def scan_files(main_frame):
    """
    Fonction pour scanner les fichiers et afficher ceux suspects avec un bouton de suppression.
    """
    # Titre de la section Scan
    label = tk.Label(
        main_frame, 
        text="Scan des fichiers :", 
        bg="white", 
        font=("Arial", 14)
    )
    label.pack(pady=20)

    # Cadre pour afficher les résultats du scan
    scan_results_frame = tk.Frame(main_frame, bg="white")
    scan_results_frame.pack(pady=10, fill="both", expand=True)

    # Liste des fichiers détectés comme suspects
    detected_files = []

    # Fonction pour simuler le scan des fichiers dans le dossier
    def start_scan():
        nonlocal detected_files
        for filename in os.listdir(SCAN_FOLDER):
            file_path = os.path.join(SCAN_FOLDER, filename)
            if os.path.isfile(file_path) and filename in SUSPECT_FILES:
                # Ajouter les fichiers suspects à la liste
                detected_files.append(filename)
                # Afficher le fichier suspect avec un bouton pour le supprimer
                file_frame = tk.Frame(scan_results_frame, bg="white")
                file_frame.pack(fill="x", pady=5)

                file_label = tk.Label(
                    file_frame, 
                    text=f"Fichier suspect: {filename}", 
                    bg="white", 
                    font=("Arial", 12),
                    anchor="w"
                )
                file_label.pack(side="left", padx=10)

                # Fonction pour supprimer le fichier
                def delete_file(file_name=filename):
                    """
                    Supprime le fichier suspect.
                    """
                    try:
                        file_path = os.path.join(SCAN_FOLDER, file_name)
                        os.remove(file_path)
                        messagebox.showinfo(
                            "Succès", 
                            f"Le fichier {file_name} a été supprimé."
                        )
                        refresh_scan_results()  # Rafraîchir la liste après suppression
                    except Exception as e:
                        messagebox.showerror(
                            "Erreur", 
                            f"Impossible de supprimer le fichier : {e}"
                        )

                # Bouton pour supprimer le fichier suspect
                delete_button = tk.Button(
                    file_frame, 
                    text="Supprimer", 
                    command=delete_file, 
                    bg="red", 
                    fg="white", 
                    font=("Arial", 10)
                )
                delete_button.pack(side="right", padx=10)

    # Bouton pour commencer le scan
    scan_button = tk.Button(
        main_frame, 
        text="Commencer le scan", 
        command=start_scan, 
        bg="#3498db", 
        fg="white", 
        font=("Arial", 12)
    )
    scan_button.pack(pady=10)

    # Fonction pour rafraîchir les résultats du scan
    def refresh_scan_results():
        for widget in scan_results_frame.winfo_children():
            widget.destroy()
        detected_files.clear()
        start_scan()

    # Initialisation du scan
    start_scan()

# Fenêtre principale
root = tk.Tk()
root.title("Gestion des rapports et scans")
root.geometry("600x400")

# Cadre principal
main_frame = tk.Frame(root, bg="white")
main_frame.pack(fill="both", expand=True, padx=20, pady=20)

# Affichage de la section des rapports
reports_section(main_frame)

# Affichage de la section de scan
scan_files(main_frame)

# Lancer l'application
root.mainloop()
