import tkinter as tk
from tkinter import filedialog, messagebox
from utils.file_scanner import scan_folder
from utils.quarantine_manager import move_to_quarantine
from utils.report_generator import generate_report

def scan_section(main_frame):
    label = tk.Label(main_frame, text="Analysez vos fichiers ou dossiers pour détecter les menaces.", bg="white", font=("Arial", 14))
    label.pack(pady=20)

    def select_folder():
        folder_path = filedialog.askdirectory()
        if folder_path:
            threats = scan_folder(folder_path)
            report_path = generate_report(threats)
            if threats:
                messagebox.showwarning(
                    "Menaces détectées",
                    f"{len(threats)} menaces détectées et enregistrées dans le rapport :\n{report_path}",
                )
            else:
                messagebox.showinfo(
                    "Aucune menace",
                    f"Aucune menace détectée. Rapport enregistré :\n{report_path}",
                )

    scan_button = tk.Button(main_frame, text="Sélectionner un dossier à scanner", command=select_folder, bg="#3498db", fg="white", font=("Arial", 12), width=25)
    scan_button.pack(pady=10)
