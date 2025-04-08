from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget
from utils.report_generator import list_reports

def report_section_widget():
    widget = QWidget()
    layout = QVBoxLayout()

    title = QLabel("📄 Rapports d'analyse")
    title.setStyleSheet("font-size: 18px; font-weight: bold;")
    layout.addWidget(title)

    reports = list_reports()

    if not reports:
        layout.addWidget(QLabel("Aucun rapport disponible."))
    else:
        report_list = QListWidget()
        for report in reports:
            report_list.addItem(report)
        layout.addWidget(report_list)

    widget.setLayout(layout)
    return widget
