import tkinter as tk
from tkinter import simpledialog, messagebox
from src.utils.updater import add_signature, update_signatures_from_url

def update_section(main_frame):
    label = tk.Label(main_frame, text="Mettez à jour la base de signatures de virus :", bg="white", font=("Arial", 14))
    label.pack(pady=20)

    # Ajouter une signature manuellement
    def add_signature_ui():
        hash_value = simpledialog.askstring("Nouvelle signature", "Entrez le hash du fichier (MD5 ou SHA256) :")
        description = simpledialog.askstring("Nouvelle signature", "Entrez la description de la menace :")
        if hash_value and description:
            if add_signature(hash_value, description):
                messagebox.showinfo("Succès", "Signature ajoutée avec succès !")
            else:
                messagebox.showerror("Erreur", "Impossible d'ajouter la signature.")

    add_button = tk.Button(main_frame, text="Ajouter une signature", command=add_signature_ui, bg="#3498db", fg="white", font=("Arial", 12))
    add_button.pack(pady=10)

    # Télécharger une mise à jour
    def update_from_url_ui():
        url = simpledialog.askstring("Mise à jour", "Entrez l'URL du fichier JSON des signatures :")
        if url:
            new_count = update_signatures_from_url(url)
            if new_count > 0:
                messagebox.showinfo("Succès", f"{new_count} nouvelles signatures ajoutées avec succès !")
            else:
                messagebox.showerror("Erreur", "Aucune nouvelle signature ajoutée ou erreur rencontrée.")

    update_button = tk.Button(main_frame, text="Télécharger les mises à jour", command=update_from_url_ui, bg="#27ae60", fg="white", font=("Arial", 12))
    update_button.pack(pady=10)
