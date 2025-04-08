from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit

def guide_section_widget():
    widget = QWidget()
    layout = QVBoxLayout()

    title = QLabel("🛡️ Guide de sécurité")
    title.setStyleSheet("font-size: 18px; font-weight: bold;")
    layout.addWidget(title)

    guide_text = QTextEdit()
    guide_text.setReadOnly(True)
    guide_text.setStyleSheet("font-family: Arial; font-size: 13px;")

    guide_content = """
Bonnes pratiques de sécurité :

- Ne cliquez pas sur des liens suspects dans les emails.
- Gardez votre système d'exploitation et vos logiciels à jour.
- Utilisez des mots de passe forts et uniques.
- Activez l'authentification à deux facteurs.
- Faites régulièrement des sauvegardes de vos données.
- Analysez les fichiers téléchargés avec un antivirus.
- Évitez les connexions Wi-Fi publiques non sécurisées.
- Désactivez les macros dans les documents Office provenant de sources inconnues.
- Vérifiez régulièrement vos comptes pour toute activité suspecte.
    """
    guide_text.setText(guide_content)
    layout.addWidget(guide_text)

    widget.setLayout(layout)
    return widget
