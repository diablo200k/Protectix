# src/gui/decision_helper.py
from PyQt5.QtCore import QObject, pyqtSlot, pyqtSignal
from PyQt5.QtWidgets import QMessageBox

class DecisionHelper(QObject):
    # Ce signal sera émis avec la décision de l'utilisateur
    decisionMade = pyqtSignal(int)
    
    @pyqtSlot(str, str)
    def ask_threat_decision(self, file_path: str, threat_source: str):
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("Menace détectée")
        msg_box.setText(f"Une menace ({threat_source}) a été détectée sur le fichier:\n{file_path}\nQue souhaitez-vous faire ?")
        delete_button = msg_box.addButton("Supprimer", QMessageBox.YesRole)
        quarantine_button = msg_box.addButton("Mettre en quarantaine", QMessageBox.NoRole)
        ignore_button = msg_box.addButton("Ignorer", QMessageBox.RejectRole)
        msg_box.exec_()
        if msg_box.clickedButton() == delete_button:
            decision = 1
        elif msg_box.clickedButton() == quarantine_button:
            decision = 2
        else:
            decision = 3
        self.decisionMade.emit(decision)
