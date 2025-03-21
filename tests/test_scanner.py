import unittest
from src.utils.file_scanner import calculate_hash, scan_directory

class TestScanner(unittest.TestCase):
    def test_calculate_hash(self):
        self.assertEqual(calculate_hash("testfile.txt"), "hash_attendu")

    def test_scan_directory(self):
        self.assertIsInstance(scan_directory("./test_directory"), list)

if __name__ == "__main__":
    unittest.main()
