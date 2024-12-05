import tkinter as tk
from tkinter import filedialog, messagebox

# Créer la fenêtre principale
root = tk.Tk()
root.title("SecuShield - Antivirus")
root.geometry("900x600")  # Taille de la fenêtre

# Ajouter une icône
# root.iconbitmap("icon.ico")  # Assurez-vous d'avoir un fichier `icon.ico`

# Créer une barre latérale
sidebar = tk.Frame(root, bg="#2c3e50", width=200, height=600)
sidebar.pack(side="left", fill="y")

# Contenu principal (section affichée)
main_frame = tk.Frame(root, bg="white", width=700, height=600)
main_frame.pack(side="right", expand=True, fill="both")

# Fonction pour afficher les sections
def show_section(section_name):
    # Effacer le contenu actuel
    for widget in main_frame.winfo_children():
        widget.destroy()

    # Ajouter un contenu en fonction de la section sélectionnée
    label = tk.Label(
        main_frame, 
        text=f"Section : {section_name}", 
        font=("Arial", 20), 
        bg="white"
    )
    label.pack(pady=10)

    # Ajout de contenu dynamique pour chaque section
    if section_name == "Scan de fichiers":
        scan_section()
    elif section_name == "Quarantaine":
        quarantine_section()
    elif section_name == "Rapports":
        report_section()
    elif section_name == "Mise à jour":
        update_section()
    elif section_name == "Guide de sécurité":
        guide_section()

# Fonctionnalité : Scan de fichiers
def scan_section():
    label = tk.Label(main_frame, text="Analysez vos fichiers ou dossiers pour détecter les menaces.", bg="white", font=("Arial", 14))
    label.pack(pady=20)

    def select_folder():
        folder_path = filedialog.askdirectory()
        if folder_path:
            messagebox.showinfo("Scan lancé", f"Scan en cours pour le dossier : {folder_path}")

    scan_button = tk.Button(main_frame, text="Sélectionner un dossier à scanner", command=select_folder, bg="#3498db", fg="white", font=("Arial", 12), width=25)
    scan_button.pack(pady=10)

# Fonctionnalité : Quarantaine
def quarantine_section():
    label = tk.Label(main_frame, text="Liste des fichiers détectés et mis en quarantaine :", bg="white", font=("Arial", 14))
    label.pack(pady=20)
    # Exemple statique (à remplacer avec une vraie liste dynamique)
    files = ["virus1.exe", "malware.doc", "trojan123.dll"]
    for file in files:
        file_label = tk.Label(main_frame, text=file, bg="white", font=("Arial", 12))
        file_label.pack(pady=5)

# Fonctionnalité : Rapports
def report_section():
    label = tk.Label(main_frame, text="Visualisez les rapports d'analyse précédents :", bg="white", font=("Arial", 14))
    label.pack(pady=20)
    message = tk.Text(main_frame, wrap="word", height=15, width=50)
    message.insert(tk.END, "Exemple de rapport :\n- Fichier : test.exe\n- Résultat : Malveillant (MD5 : ...)")
    message.pack(pady=10)

# Fonctionnalité : Mise à jour de la base
def update_section():
    label = tk.Label(main_frame, text="Mettez à jour la base de signatures de virus.", bg="white", font=("Arial", 14))
    label.pack(pady=20)

    def update_signatures():
        # Simulation de mise à jour
        messagebox.showinfo("Mise à jour", "Base de signatures mise à jour avec succès!")

    update_button = tk.Button(main_frame, text="Mettre à jour", command=update_signatures, bg="#27ae60", fg="white", font=("Arial", 12), width=20)
    update_button.pack(pady=10)

# Fonctionnalité : Guide de sécurité
def guide_section():
    label = tk.Label(main_frame, text="Conseils de sécurité informatique :", bg="white", font=("Arial", 14))
    label.pack(pady=20)
    tips = [
        
        "1. Ne téléchargez que depuis des sources fiables.",
        "2. Mettez à jour régulièrement votre système et vos logiciels.",
        "3. Ne cliquez pas sur des liens suspects dans les e-mails.",
        "4. Utilisez des mots de passe forts et uniques.",
    ]
    for tip in tips:
        tip_label = tk.Label(main_frame, text=tip, bg="white", font=("Arial", 12))
        tip_label.pack(pady=5)



# Ajouter des boutons dans la barre latérale
buttons = [
    ("Accueil", lambda: show_section("Accueil")),
    ("Scan de fichiers", lambda: show_section("Scan de fichiers")),
    ("Quarantaine", lambda: show_section("Quarantaine")),
    ("Rapports", lambda: show_section("Rapports")),
    ("Mise à jour", lambda: show_section("Mise à jour")),
    ("Guide de sécurité", lambda: show_section("Guide de sécurité")),
]


# Créer les boutons

for text, command in buttons:
    button = tk.Button(
        sidebar, 
        text=text, 
        command=command, 
        bg="#34495e", 
        fg="white", 
        bd=0, 
        height=2, 
        font=("Arial", 12)
    )
    button.pack(fill="x")

# Lancer l'interface
show_section("Accueil")  # Afficher la section "Accueil" par défaut
root.mainloop()
