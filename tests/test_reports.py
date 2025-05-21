import unittest
import os
import json
import shutil
from src.utils.report_generator import ReportGenerator

class TestReports(unittest.TestCase):
    """Tests pour le module de génération et gestion des rapports."""
    
    def setUp(self):
        """Configuration initiale pour les tests."""
        # Définir un répertoire temporaire pour les tests
        self.test_report_dir = os.path.abspath("./test_reports")
        
        # Sauvegarder la valeur d'origine du répertoire des rapports
        self.original_report_dir = ReportGenerator.REPORT_DIR
        
        # Utiliser le répertoire de test pendant les tests
        ReportGenerator.REPORT_DIR = self.test_report_dir
        
        # Créer le répertoire temporaire s'il n'existe pas
        if not os.path.exists(self.test_report_dir):
            os.makedirs(self.test_report_dir)
        
        # Exemple de menaces pour les tests
        self.mock_threats = [
            {
                "file": "/path/to/suspicious/file.exe",
                "hash": "a1b2c3d4e5f6g7h8i9j0",
                "source": "virustotal",
                "malicious": 5,
                "suspicious": 2,
                "decision": 2  # Mis en quarantaine
            },
            {
                "file": "/path/to/another/malware.dll",
                "hash": "9i8h7g6f5e4d3c2b1a0",
                "source": "local",
                "threat": "suspicious_behavior",
                "decision": 1  # Supprimé
            }
        ]
        
        # Exemple d'informations de scan
        self.mock_scan_info = {
            "directory": "/path/to/scanned/directory",
            "files_scanned": 150,
            "scan_duration": 45.7
        }
    
    def tearDown(self):
        """Nettoyage après les tests."""
        # Restaurer la valeur d'origine du répertoire des rapports
        ReportGenerator.REPORT_DIR = self.original_report_dir
        
        # Supprimer le répertoire temporaire et son contenu
        if os.path.exists(self.test_report_dir):
            shutil.rmtree(self.test_report_dir)
    
    def test_generate_report(self):
        """Teste la génération de rapport."""
        report_paths = ReportGenerator.generate_report(self.mock_threats, self.mock_scan_info)
        
        # Vérifier que les fichiers ont été créés
        self.assertTrue(os.path.exists(report_paths["html"]))
        self.assertTrue(os.path.exists(report_paths["json"]))
        self.assertTrue(os.path.exists(report_paths["txt"]))
        
        # Vérifier le contenu du rapport JSON
        with open(report_paths["json"], 'r', encoding='utf-8') as f:
            report_data = json.load(f)
            
            # Vérifier que les données sont correctes
            self.assertEqual(len(report_data["threats"]), 2)
            self.assertEqual(report_data["scan_info"]["files_scanned"], 150)
            self.assertEqual(report_data["scan_info"]["scan_duration"], 45.7)
            
            # Vérifier que les informations système sont présentes
            self.assertIn("system_info", report_data)
            self.assertIn("os", report_data["system_info"])
            self.assertIn("python", report_data["system_info"])
    
    def test_list_reports(self):
        """Teste la récupération de la liste des rapports."""
        # Générer deux rapports
        report1 = ReportGenerator.generate_report(self.mock_threats, self.mock_scan_info)
        report2 = ReportGenerator.generate_report([], self.mock_scan_info)
        
        # Vérifier que les rapports sont listés
        reports = ReportGenerator.list_reports()
        self.assertEqual(len(reports), 2)
        
        # Vérifier que les rapports sont triés par date (du plus récent au plus ancien)
        self.assertEqual(reports[0]["id"], report2["id"])
        self.assertEqual(reports[1]["id"], report1["id"])
        
        # Vérifier que les informations sont correctes
        self.assertEqual(reports[0]["threat_count"], 0)
        self.assertEqual(reports[1]["threat_count"], 2)
    
    def test_get_report(self):
        """Teste la récupération d'un rapport spécifique."""
        # Générer un rapport
        report_paths = ReportGenerator.generate_report(self.mock_threats, self.mock_scan_info)
        report_id = report_paths["id"]
        
        # Récupérer le rapport
        report_data = ReportGenerator.get_report(report_id)
        
        # Vérifier que les données sont correctes
        self.assertIsNotNone(report_data)
        self.assertEqual(report_data["report_id"], report_id)
        self.assertEqual(len(report_data["threats"]), 2)
        
        # Tester avec un ID inexistant
        self.assertIsNone(ReportGenerator.get_report("non_existent_id"))
    
    def test_delete_report(self):
        """Teste la suppression d'un rapport."""
        # Générer un rapport
        report_paths = ReportGenerator.generate_report(self.mock_threats, self.mock_scan_info)
        report_id = report_paths["id"]
        
        # Vérifier que les fichiers existent
        self.assertTrue(os.path.exists(report_paths["html"]))
        self.assertTrue(os.path.exists(report_paths["json"]))
        self.assertTrue(os.path.exists(report_paths["txt"]))
        
        # Supprimer le rapport
        result = ReportGenerator.delete_report(report_id)
        self.assertTrue(result)
        
        # Vérifier que les fichiers ont été supprimés
        self.assertFalse(os.path.exists(report_paths["html"]))
        self.assertFalse(os.path.exists(report_paths["json"]))
        self.assertFalse(os.path.exists(report_paths["txt"]))
        
        # Vérifier que le rapport n'est plus listé
        reports = ReportGenerator.list_reports()
        self.assertEqual(len(reports), 0)
    
    def test_empty_threats(self):
        """Teste la génération d'un rapport sans menaces."""
        report_paths = ReportGenerator.generate_report([], self.mock_scan_info)
        
        # Vérifier que les fichiers ont été créés
        self.assertTrue(os.path.exists(report_paths["html"]))
        
        # Vérifier le contenu du rapport JSON
        with open(report_paths["json"], 'r', encoding='utf-8') as f:
            report_data = json.load(f)
            
            # Vérifier que la liste des menaces est vide
            self.assertEqual(len(report_data["threats"]), 0)
    
    def test_compatibility_functions(self):
        """Teste les fonctions de compatibilité avec l'ancien code."""
        # Importer les fonctions de compatibilité
        from src.utils.report_generator import generate_report, list_reports
        
        # Générer un rapport avec l'ancienne fonction
        report_path = generate_report(self.mock_threats, self.mock_scan_info)
        
        # Vérifier que le fichier a été créé
        self.assertTrue(os.path.exists(report_path))
        
        # Vérifier que la fonction list_reports retourne une liste de strings
        reports = list_reports()
        self.assertTrue(all(isinstance(r, str) for r in reports))


if __name__ == "__main__":
    unittest.main()