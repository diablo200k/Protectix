import tkinter as tk
from src.gui.scan_section import scan_section
from src.gui.quarantine_section import quarantine_section
from src.gui.reports_section import reports_section
from src.gui.update_section import update_section
from src.gui.guide_section import guide_section

def main():
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
    def show_section(section_name, button):
        # Supprimer tous les widgets existants dans main_frame
        for widget in main_frame.winfo_children():
            widget.destroy()

        # Charger la section appropriée
        if section_name == "Scan de fichiers":
            scan_section(main_frame)
        elif section_name == "Quarantaine":
            quarantine_section(main_frame)
        elif section_name == "Rapports":
            reports_section(main_frame)
        elif section_name == "Mise à jour":
            update_section(main_frame)
        elif section_name == "Guide de sécurité":
            guide_section(main_frame)

        # Afficher un message de confirmation
        confirmation_label = tk.Label(main_frame, text=f"Section : {section_name}", font=("Arial", 14), fg="#3498db")
        confirmation_label.pack(pady=10)

    # Ajouter des boutons dans la barre latérale
    buttons = [
        ("Scan de fichiers", lambda: show_section("Scan de fichiers", button)),
        ("Quarantaine", lambda: show_section("Quarantaine", button)),
        ("Rapports", lambda: show_section("Rapports", button)),
        ("Mise à jour", lambda: show_section("Mise à jour", button)),
        ("Guide de sécurité", lambda: show_section("Guide de sécurité", button)),
    ]

    for text, command in buttons:
        button = tk.Button(
            sidebar, text=text, command=command, bg="#34495e", fg="white", bd=0, height=2, font=("Arial", 12)
        )
        button.pack(fill="x")

    # Afficher la section par défaut
    show_section("Scan de fichiers", None)

    # Lancer l'application
    root.mainloop()

# Exécuter l'application
if __name__ == "__main__":
    main()
