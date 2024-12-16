import os
from datetime import datetime

# Définir le dossier où les rapports seront enregistrés
REPORTS_FOLDER = "data/reports"

def ensure_reports_folder_exists():
    """Crée le dossier de rapports s'il n'existe pas."""
    if not os.path.exists(REPORTS_FOLDER):
        os.makedirs(REPORTS_FOLDER)

def generate_report(threats):
    """
    Génère un rapport d'analyse.
    :param threats: Liste des menaces détectées (chaque élément est un dict avec 'file' et 'threat').
    :return: Chemin du rapport généré.
    """
    ensure_reports_folder_exists()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = os.path.join(REPORTS_FOLDER, f"report_{timestamp}.txt")

    with open(report_file, "w") as file:
        file.write("=== SecuShield Antivirus Report ===\n")
        file.write(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        if threats:
            file.write("Menaces détectées :\n")
            for threat in threats:
                file.write(f"- Fichier : {threat['file']}, Menace : {threat['threat']}\n")
        else:
            file.write("Aucune menace détectée.\n")
        file.write("\n=== Fin du rapport ===\n")

    return report_file
