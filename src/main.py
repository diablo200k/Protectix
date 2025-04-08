import sys
import os

# Ajouter src/ au chemin Python pour les imports internes
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

# Importer la fonction qui lance l'interface depuis main_gui.py
from gui.main_gui import run_gui

if __name__ == "__main__":
    run_gui()  # Appelle la fonction qui crée la fenêtre et lance le mainloop
