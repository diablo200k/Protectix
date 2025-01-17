import os
from datetime import datetime

REPORT_DIR = "../data/reports"

def generate_report(threats):
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)
    report_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    report_path = os.path.join(REPORT_DIR, report_name)
    with open(report_path, 'w') as report:
        for threat in threats:
            report.write(f"Fichier : {threat['file']}, Menace : {threat['threat']}\n")
    return report_path

def list_reports():
    if not os.path.exists(REPORT_DIR):
        return []
    return os.listdir(REPORT_DIR)
