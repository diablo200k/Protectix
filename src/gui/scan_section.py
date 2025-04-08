from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QMessageBox
)
from utils.file_scanner import scan_directory as scan_folder


def scan_section_widget():
    widget = QWidget()
    layout = QVBoxLayout()

    title_label = QLabel("Analysez vos fichiers ou dossiers pour détecter les menaces.")
    title_label.setStyleSheet("font-size: 16px;")
    layout.addWidget(title_label)

    def select_folder():
        folder_path = QFileDialog.getExistingDirectory(widget, "Sélectionner un dossier")
        if folder_path:
            threats = scan_folder(folder_path)
            if threats:
                QMessageBox.warning(widget, "Menaces détectées", f"{len(threats)} menaces détectées ! Consultez les rapports.")
                layout.addWidget(QLabel("Menaces détectées :"))
                for threat in threats:
                    threat_label = QLabel(f"- {threat['file']} ({threat['threat']})")
                    layout.addWidget(threat_label)
            else:
                QMessageBox.information(widget, "Aucune menace", "Aucune menace détectée dans le dossier scanné.")

    scan_btn = QPushButton("Sélectionner un dossier à scanner")
    scan_btn.setStyleSheet("background-color: #3498db; color: white; font-size: 14px; padding: 6px 10px;")
    scan_btn.clicked.connect(select_folder)
    layout.addWidget(scan_btn)

    widget.setLayout(layout)
    return widget
