from PyQt5.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QListWidget, QHBoxLayout,
    QPushButton, QMessageBox
)
from PyQt5.QtCore import Qt
from utils.quarantine_manager import list_quarantine, restore_file, delete_from_quarantine

def quarantine_section_widget():
    widget = QWidget()
    main_layout = QVBoxLayout(widget)
    main_layout.setContentsMargins(15, 15, 15, 15)
    main_layout.setSpacing(10)

    # Titre de la section
    title = QLabel("Zone de Quarantaine")
    title.setStyleSheet("font-size: 20px; font-weight: bold; color: #2c3e50;")
    main_layout.addWidget(title)

    # Liste des fichiers en quarantaine
    list_widget = QListWidget()
    list_widget.setStyleSheet("""
        QListWidget {
            font-size: 14px;
            padding: 5px;
        }
        QListWidget::item {
            padding: 8px;
            margin: 2px;
        }
        QListWidget::item:selected {
            background-color: #3498db;
            color: white;
        }
    """)
    main_layout.addWidget(list_widget)

    # Layout pour les boutons d'action
    button_layout = QHBoxLayout()
    restore_button = QPushButton("Restaurer")
    delete_button = QPushButton("Supprimer définitivement")
    refresh_button = QPushButton("Rafraîchir")
    
    # Style des boutons
    for btn in (restore_button, delete_button, refresh_button):
        btn.setStyleSheet("font-size: 14px; padding: 6px;")
    button_layout.addWidget(restore_button)
    button_layout.addWidget(delete_button)
    button_layout.addWidget(refresh_button)
    main_layout.addLayout(button_layout)

    # Label pour afficher les messages ou résultats
    message_label = QLabel("")
    message_label.setStyleSheet("font-size: 14px; color: #e74c3c;")
    main_layout.addWidget(message_label)

    def load_quarantine_list():
        list_widget.clear()
        files = list_quarantine()
        if not files:
            list_widget.addItem("Aucun fichier en quarantaine.")
            restore_button.setEnabled(False)
            delete_button.setEnabled(False)
        else:
            for file_name in files:
                list_widget.addItem(file_name)
            restore_button.setEnabled(True)
            delete_button.setEnabled(True)

    load_quarantine_list()

    def on_restore():
        current_item = list_widget.currentItem()
        if current_item is None or current_item.text() == "Aucun fichier en quarantaine.":
            QMessageBox.information(widget, "Information", "Veuillez sélectionner un fichier à restaurer.")
            return
        file_name = current_item.text()
        response = restore_file(file_name)
        QMessageBox.information(widget, "Restauration", response)
        load_quarantine_list()

    def on_delete():
        current_item = list_widget.currentItem()
        if current_item is None or current_item.text() == "Aucun fichier en quarantaine.":
            QMessageBox.information(widget, "Information", "Veuillez sélectionner un fichier à supprimer.")
            return
        file_name = current_item.text()
        confirm = QMessageBox.question(
            widget,
            "Confirmation",
            f"Êtes-vous sûr de vouloir supprimer définitivement '{file_name}' ?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            response = delete_from_quarantine(file_name)
            QMessageBox.information(widget, "Suppression", response)
            load_quarantine_list()

    restore_button.clicked.connect(on_restore)
    delete_button.clicked.connect(on_delete)
    refresh_button.clicked.connect(load_quarantine_list)

    widget.setLayout(main_layout)
    return widget
