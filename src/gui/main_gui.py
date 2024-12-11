import tkinter as tk
from gui.scan_section import scan_section
from gui.quarantine_section import quarantine_section
from gui.reports_section import report_section
from gui.update_section import update_section
from gui.guide_section import guide_section

# Créer la fenêtre principale
root = tk.Tk()
root.title("SecuShield - Antivirus")
root.geometry("900x600")

# Créer une barre latérale
sidebar = tk.Frame(root, bg="#2c3e50", width=200, height=600)
sidebar.pack(side="left", fill="y")

# Contenu principal (section affichée)
main_frame = tk.Frame(root, bg="white", width=700, height=600)
main_frame.pack(side="right", expand=True, fill="both")

# Fonction pour afficher les sections
def show_section(section_name):
    for widget in main_frame.winfo_children():
        widget.destroy()

    if section_name == "Scan de fichiers":
        scan_section(main_frame)
    elif section_name == "Quarantaine":
        quarantine_section(main_frame)
    elif section_name == "Rapports":
        report_section(main_frame)
    elif section_name == "Mise à jour":
        update_section(main_frame)
    elif section_name == "Guide de sécurité":
        guide_section(main_frame)

# Ajouter des boutons dans la barre latérale
buttons = [
    ("Scan de fichiers", lambda: show_section("Scan de fichiers")),
    ("Quarantaine", lambda: show_section("Quarantaine")),
    ("Rapports", lambda: show_section("Rapports")),
    ("Mise à jour", lambda: show_section("Mise à jour")),
    ("Guide de sécurité", lambda: show_section("Guide de sécurité")),
]

for text, command in buttons:
    button = tk.Button(
        sidebar, text=text, command=command, bg="#34495e", fg="white", bd=0, height=2, font=("Arial", 12)
    )
    button.pack(fill="x")

# Afficher la section par défaut
show_section("Scan de fichiers")
root.mainloop()
