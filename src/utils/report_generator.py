import os
import json
from datetime import datetime
import platform
import psutil
import time
import html

# Utilisation d'un chemin absolu pour éviter les problèmes de chemin relatif
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data"))
REPORT_DIR = os.path.join(BASE_DIR, "reports")

class ReportGenerator:
    """Classe pour la génération et la gestion des rapports d'analyse antivirus."""
    
    @staticmethod
    def generate_report(threats, scan_info=None):
        """
        Génère un rapport détaillé au format HTML et JSON pour les menaces détectées.
        
        Args:
            threats (list): Liste des menaces détectées
            scan_info (dict, optional): Informations sur le scan (durée, fichiers analysés, etc.)
        
        Returns:
            dict: Chemins des rapports générés (html et json)
        """
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)
            
        # Informations de base
        timestamp = datetime.now()
        report_id = timestamp.strftime('%Y%m%d_%H%M%S')
        report_name_base = f"report_{report_id}"
        
        # Rapport au format JSON (pour le traitement programmatique)
        json_path = os.path.join(REPORT_DIR, f"{report_name_base}.json")
        
        # Données du rapport
        report_data = {
            "report_id": report_id,
            "timestamp": timestamp.isoformat(),
            "threats": threats,
            "scan_info": scan_info or {},
            "system_info": {
                "os": platform.platform(),
                "python": platform.python_version(),
                "hostname": platform.node(),
                "cpu_count": psutil.cpu_count(),
                "memory": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB"
            }
        }
        
        # Sauvegarde du rapport JSON
        with open(json_path, 'w', encoding='utf-8') as json_file:
            json.dump(report_data, json_file, ensure_ascii=False, indent=2)
        
        # Génération du rapport HTML
        html_path = os.path.join(REPORT_DIR, f"{report_name_base}.html")
        with open(html_path, 'w', encoding='utf-8') as html_file:
            html_file.write(ReportGenerator._generate_html_report(report_data))
        
        # Génération du rapport au format texte simple (pour la compatibilité)
        txt_path = os.path.join(REPORT_DIR, f"{report_name_base}.txt")
        with open(txt_path, 'w', encoding='utf-8') as txt_file:
            ReportGenerator._generate_text_report(report_data, txt_file)
        
        return {
            "json": json_path,
            "html": html_path,
            "txt": txt_path,
            "id": report_id
        }
    
    @staticmethod
    def _generate_html_report(report_data):
        """Génère le contenu HTML du rapport."""
        threats = report_data["threats"]
        scan_info = report_data["scan_info"]
        system_info = report_data["system_info"]
        
        # Entête HTML
        html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'analyse - SecuShield</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .warning {{ background-color: #ffe6e6; border-left: 5px solid #e74c3c; padding: 10px; margin-bottom: 5px; }}
        .ok {{ background-color: #e6ffe6; border-left: 5px solid #2ecc71; padding: 10px; margin-bottom: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .footer {{ margin-top: 30px; text-align: center; font-size: 12px; color: #777; }}
        .malicious {{ color: #e74c3c; font-weight: bold; }}
        .suspicious {{ color: #f39c12; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SecuShield - Rapport d'analyse antivirus</h1>
            <p>Généré le: {datetime.fromisoformat(report_data["timestamp"]).strftime('%d/%m/%Y à %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>Résumé</h2>
            <p><strong>Menaces détectées:</strong> {len(threats)}</p>
"""
        
        # Informations de scan
        if scan_info:
            html_content += f"""
            <p><strong>Dossier analysé:</strong> {scan_info.get('directory', 'N/A')}</p>
            <p><strong>Fichiers analysés:</strong> {scan_info.get('files_scanned', 0)}</p>
            <p><strong>Durée du scan:</strong> {scan_info.get('scan_duration', 0)} secondes</p>
"""
        
        # Informations système
        html_content += f"""
        </div>
        
        <h2>Informations système</h2>
        <table>
            <tr>
                <th>Système d'exploitation</th>
                <td>{system_info.get('os', 'N/A')}</td>
            </tr>
            <tr>
                <th>Version Python</th>
                <td>{system_info.get('python', 'N/A')}</td>
            </tr>
            <tr>
                <th>Nom d'hôte</th>
                <td>{system_info.get('hostname', 'N/A')}</td>
            </tr>
            <tr>
                <th>Processeur</th>
                <td>{system_info.get('cpu_count', 'N/A')} cœurs</td>
            </tr>
            <tr>
                <th>Mémoire</th>
                <td>{system_info.get('memory', 'N/A')}</td>
            </tr>
        </table>
"""
        
        # Détails des menaces
        html_content += """
        <h2>Détails des menaces</h2>
"""
        
        if threats:
            html_content += """
        <table>
            <tr>
                <th>Fichier</th>
                <th>Type de menace</th>
                <th>Source</th>
                <th>Hash</th>
                <th>Action</th>
            </tr>
"""
            for threat in threats:
                file_path = html.escape(threat.get('file', 'N/A'))
                threat_type = threat.get('threat', threat.get('source', 'N/A'))
                source = threat.get('source', 'N/A')
                hash_value = threat.get('hash', 'N/A')
                
                # Déterminer l'action prise
                decision = threat.get('decision', 0)
                if decision == 1:
                    action = "Supprimé"
                elif decision == 2:
                    action = "Mis en quarantaine"
                elif decision == 3:
                    action = "Ignoré"
                else:
                    action = "Aucune action"
                
                # Déterminer le style selon le niveau de risque
                threat_class = ""
                if source == 'virustotal':
                    malicious = threat.get('malicious', 0)
                    if malicious > 0:
                        threat_class = "malicious"
                        threat_type = f"Malicieux ({malicious} détections)"
                    else:
                        suspicious = threat.get('suspicious', 0)
                        if suspicious > 0:
                            threat_class = "suspicious"
                            threat_type = f"Suspect ({suspicious} détections)"
                
                html_content += f"""
            <tr>
                <td>{file_path}</td>
                <td class="{threat_class}">{threat_type}</td>
                <td>{source}</td>
                <td>{hash_value}</td>
                <td>{action}</td>
            </tr>
"""
            
            html_content += """
        </table>
"""
        else:
            html_content += """
        <p class="ok">Aucune menace n'a été détectée lors de cette analyse.</p>
"""
        
        # Pied de page
        html_content += """
        <div class="footer">
            <p>Ce rapport a été généré par SecuShield Antivirus. © 2024 SecuShield</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html_content
    
    @staticmethod
    def _generate_text_report(report_data, file_obj):
        """Génère le contenu texte du rapport."""
        threats = report_data["threats"]
        scan_info = report_data["scan_info"]
        system_info = report_data["system_info"]
        
        # Entête
        file_obj.write("=============================================\n")
        file_obj.write("  RAPPORT D'ANALYSE ANTIVIRUS - SECUSHIELD   \n")
        file_obj.write("=============================================\n\n")
        
        # Date et heure
        file_obj.write(f"Généré le: {datetime.fromisoformat(report_data['timestamp']).strftime('%d/%m/%Y à %H:%M:%S')}\n\n")
        
        # Résumé
        file_obj.write("RÉSUMÉ\n")
        file_obj.write("-----------\n")
        file_obj.write(f"Menaces détectées: {len(threats)}\n")
        
        if scan_info:
            file_obj.write(f"Dossier analysé: {scan_info.get('directory', 'N/A')}\n")
            file_obj.write(f"Fichiers analysés: {scan_info.get('files_scanned', 0)}\n")
            file_obj.write(f"Durée du scan: {scan_info.get('scan_duration', 0)} secondes\n")
        
        file_obj.write("\nINFORMATIONS SYSTÈME\n")
        file_obj.write("--------------------\n")
        file_obj.write(f"Système d'exploitation: {system_info.get('os', 'N/A')}\n")
        file_obj.write(f"Version Python: {system_info.get('python', 'N/A')}\n")
        file_obj.write(f"Nom d'hôte: {system_info.get('hostname', 'N/A')}\n")
        file_obj.write(f"Processeur: {system_info.get('cpu_count', 'N/A')} cœurs\n")
        file_obj.write(f"Mémoire: {system_info.get('memory', 'N/A')}\n")
        
        # Détails des menaces
        file_obj.write("\nDÉTAILS DES MENACES\n")
        file_obj.write("-------------------\n")
        
        if threats:
            for i, threat in enumerate(threats, 1):
                file_obj.write(f"Menace #{i}:\n")
                file_obj.write(f"  Fichier: {threat.get('file', 'N/A')}\n")
                
                # Source et type de la menace
                source = threat.get('source', 'N/A')
                file_obj.write(f"  Source: {source}\n")
                
                if source == 'virustotal':
                    malicious = threat.get('malicious', 0)
                    suspicious = threat.get('suspicious', 0)
                    file_obj.write(f"  Détections malicieuses: {malicious}\n")
                    file_obj.write(f"  Détections suspectes: {suspicious}\n")
                else:
                    file_obj.write(f"  Type de menace: {threat.get('threat', 'N/A')}\n")
                
                file_obj.write(f"  Hash: {threat.get('hash', 'N/A')}\n")
                
                # Action prise
                decision = threat.get('decision', 0)
                if decision == 1:
                    action = "Supprimé"
                elif decision == 2:
                    action = "Mis en quarantaine"
                elif decision == 3:
                    action = "Ignoré"
                else:
                    action = "Aucune action"
                file_obj.write(f"  Action: {action}\n\n")
        else:
            file_obj.write("Aucune menace n'a été détectée lors de cette analyse.\n")
    
    @staticmethod
    def list_reports():
        """
        Liste tous les rapports disponibles.
        
        Returns:
            list: Liste de dictionnaires contenant les informations sur chaque rapport
        """
        if not os.path.exists(REPORT_DIR):
            return []
        
        reports = []
        for filename in os.listdir(REPORT_DIR):
            if filename.startswith("report_") and filename.endswith(".json"):
                try:
                    # Extraire l'ID du rapport du nom de fichier
                    report_id = filename.replace("report_", "").replace(".json", "")
                    json_path = os.path.join(REPORT_DIR, filename)
                    
                    # Lire les métadonnées du rapport
                    with open(json_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # Ajouter les informations de rapport à la liste
                    reports.append({
                        "id": report_id,
                        "timestamp": data.get("timestamp", ""),
                        "threat_count": len(data.get("threats", [])),
                        "paths": {
                            "json": json_path,
                            "html": json_path.replace(".json", ".html"),
                            "txt": json_path.replace(".json", ".txt")
                        }
                    })
                except Exception as e:
                    print(f"Erreur lors de la lecture du rapport {filename}: {e}")
        
        # Trier les rapports par date (du plus récent au plus ancien)
        reports.sort(key=lambda x: x["timestamp"], reverse=True)
        return reports
    
    @staticmethod
    def get_report(report_id):
        """
        Récupère les détails d'un rapport spécifique.
        
        Args:
            report_id (str): Identifiant du rapport
            
        Returns:
            dict: Données du rapport, ou None si non trouvé
        """
        json_path = os.path.join(REPORT_DIR, f"report_{report_id}.json")
        if not os.path.exists(json_path):
            return None
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Erreur lors de la lecture du rapport {report_id}: {e}")
            return None
    
    @staticmethod
    def delete_report(report_id):
        """
        Supprime un rapport et tous ses fichiers associés.
        
        Args:
            report_id (str): Identifiant du rapport
            
        Returns:
            bool: True si suppression réussie, False sinon
        """
        try:
            base_path = os.path.join(REPORT_DIR, f"report_{report_id}")
            for ext in [".json", ".html", ".txt"]:
                file_path = f"{base_path}{ext}"
                if os.path.exists(file_path):
                    os.remove(file_path)
            return True
        except Exception as e:
            print(f"Erreur lors de la suppression du rapport {report_id}: {e}")
            return False


# Pour la compatibilité avec le code existant
def generate_report(threats, scan_info=None):
    """
    Version fonctionnelle de la génération de rapport pour la compatibilité.
    
    Args:
        threats (list): Liste des menaces détectées
        scan_info (dict, optional): Informations sur le scan
        
    Returns:
        str: Chemin du rapport texte généré
    """
    report_paths = ReportGenerator.generate_report(threats, scan_info)
    return report_paths["txt"]  # Retourne le chemin du fichier texte pour la compatibilité

def list_reports():
    """
    Version fonctionnelle de la liste des rapports pour la compatibilité.
    
    Returns:
        list: Liste des noms de fichiers des rapports
    """
    reports = ReportGenerator.list_reports()
    return [f"report_{report['id']}.html" for report in reports]