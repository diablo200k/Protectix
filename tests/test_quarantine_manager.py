import unittest
from src.utils.quarantine_manager import move_to_quarantine, list_quarantine, restore_file, delete_from_quarantine

class TestQuarantineManager(unittest.TestCase):
    def test_move_to_quarantine(self):
        result = move_to_quarantine("testfile.txt")
        self.assertIn("Fichier déplacé en quarantaine", result)

    def test_list_quarantine(self):
        files = list_quarantine()
        self.assertIsInstance(files, list)

    def test_restore_file(self):
        result = restore_file("testfile.txt")
        self.assertIn("Fichier restauré", result)

    def test_delete_from_quarantine(self):
        result = delete_from_quarantine("testfile.txt")
        self.assertIn("Fichier supprimé définitivement", result)

if __name__ == "__main__":
    unittest.main()
