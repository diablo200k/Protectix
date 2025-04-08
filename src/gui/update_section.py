from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox

def update_section_widget():
    widget = QWidget()
    layout = QVBoxLayout()

    title = QLabel("🔄 Mise à jour des signatures")
    title.setStyleSheet("font-size: 18px; font-weight: bold;")
    layout.addWidget(title)

    info_label = QLabel("Vérifiez et mettez à jour la base de signatures.")
    layout.addWidget(info_label)

    def check_for_updates():
        # Ici on pourrait implémenter un vrai système d'update avec fetch depuis GitHub ou VirusShare
        QMessageBox.information(widget, "Mise à jour", "Les signatures sont à jour.")

    update_button = QPushButton("Vérifier les mises à jour")
    update_button.clicked.connect(check_for_updates)
    layout.addWidget(update_button)

    widget.setLayout(layout)
    return widget
