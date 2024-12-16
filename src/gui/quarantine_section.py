import tkinter as tk
from tkinter import messagebox, filedialog
from utils.quarantine_manager import list_quarantined_files, restore_file, delete_file

def quarantine_section(main_frame):
    label = tk.Label(main_frame, text="Liste des fichiers détectés et mis en quarantaine :", bg="white", font=("Arial", 14))
    label.pack(pady=20)

    # Cadre pour afficher la liste des fichiers
    file_list_frame = tk.Frame(main_frame, bg="white")
    file_list_frame.pack(pady=10)

    # Actualiser la liste des fichiers en quarantaine
    def refresh_quarantine_list():
        for widget in file_list_frame.winfo_children():
            widget.destroy()

        files = list_quarantined_files()
        if not files:
            no_files_label = tk.Label(file_list_frame, text="Aucun fichier en quarantaine.", bg="white", font=("Arial", 12))
            no_files_label.pack()
        else:
            for file_name in files:
                file_frame = tk.Frame(file_list_frame, bg="white")
                file_frame.pack(pady=5, fill="x")

                file_label = tk.Label(file_frame, text=file_name, bg="white", font=("Arial", 12))
                file_label.pack(side="left", padx=10)

                def restore(file=file_name):
                    original_path = filedialog.askdirectory(title="Sélectionnez l'emplacement de restauration")
                    if original_path:
                        if restore_file(file, original_path):
                            messagebox.showinfo("Restauration réussie", f"Le fichier {file} a été restauré avec succès.")
                            refresh_quarantine_list()
                        else:
                            messagebox.showerror("Erreur", f"Impossible de restaurer le fichier {file}.")

                restore_button = tk.Button(file_frame, text="Restaurer", command=restore, bg="#27ae60", fg="white", font=("Arial", 10))
                restore_button.pack(side="right", padx=5)

                def delete(file=file_name):
                    if messagebox.askyesno("Confirmation", f"Voulez-vous vraiment supprimer le fichier {file} ?"):
                        if delete_file(file):
                            messagebox.showinfo("Suppression réussie", f"Le fichier {file} a été supprimé avec succès.")
                            refresh_quarantine_list()
                        else:
                            messagebox.showerror("Erreur", f"Impossible de supprimer le fichier {file}.")

                delete_button = tk.Button(file_frame, text="Supprimer", command=delete, bg="#c0392b", fg="white", font=("Arial", 10))
                delete_button.pack(side="right", padx=5)

    # Ajouter un bouton pour actualiser la liste
    refresh_button = tk.Button(main_frame, text="Actualiser", command=refresh_quarantine_list, bg="#3498db", fg="white", font=("Arial", 12))
    refresh_button.pack(pady=10)

    refresh_quarantine_list()
