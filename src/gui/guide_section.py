import tkinter as tk

def guide_section(frame):
    """
    Fonction pour afficher le guide de sécurité.
    """
    label = tk.Label(frame, text="Guide de sécurité", bg="white", font=("Arial", 14))
    label.pack(pady=20)

    content = """Bienvenue dans le guide de sécurité :
    - Gardez vos fichiers à jour.
    - Analysez régulièrement votre système.
    - Évitez les téléchargements suspects.
    """
    guide_label = tk.Label(frame, text=content, bg="white", justify="left", font=("Arial", 12))
    guide_label.pack(padx=10, pady=10)
