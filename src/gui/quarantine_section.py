from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout

def quarantine_section_widget():
    widget = QWidget()
    layout = QVBoxLayout()
    label = QLabel("Zone de quarantaine (en développement)")
    layout.addWidget(label)
    widget.setLayout(layout)
    return widget
