import sys
import os

# Ajouter le dossier parent au chemin Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from gui import *  # Importer le module `gui` de `src`

if __name__ == "__main__":
    root.mainloop()
