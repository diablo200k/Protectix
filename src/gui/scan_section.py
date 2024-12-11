import tkinter as tk
from tkinter import filedialog, messagebox
from utils.file_scanner import scan_folder

def scan_section(main_frame):
    label = tk.Label(main_frame, text="Analysez vos fichiers ou dossiers pour détecter les menaces.", bg="white", font=("Arial", 14))
    label.pack(pady=20)

    def select_folder():
        folder_path = filedialog.askdirectory()
        if folder_path:
            threats = scan_folder(folder_path)
            if threats:
                messagebox.showwarning("Menaces détectées", f"{len(threats)} menaces détectées ! Consultez les rapports.")
                # Afficher les menaces dans l'interface
                result_label = tk.Label(main_frame, text="Menaces détectées :", bg="white", font=("Arial", 14))
                result_label.pack(pady=10)
                for threat in threats:
                    threat_label = tk.Label(main_frame, text=f"- {threat['file']} ({threat['threat']})", bg="white", font=("Arial", 12))
                    threat_label.pack(pady=5)
            else:
                messagebox.showinfo("Aucune menace", "Aucune menace détectée dans le dossier scanné.")

    scan_button = tk.Button(main_frame, text="Sélectionner un dossier à scanner", command=select_folder, bg="#3498db", fg="white", font=("Arial", 12), width=25)
    scan_button.pack(pady=10)
