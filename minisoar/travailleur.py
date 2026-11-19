"""Lance un travailleur de la file durable.

    python -m minisoar.travailleur              # boucle sans fin
    python -m minisoar.travailleur --une-fois   # vide la file puis s'arrête

Avec SOAR_MODE=durable (ou ia), le travailleur gère aussi les cas et les approbations humaines.
"""
import os, sys

from minisoar import file, cas

if __name__ == "__main__":
    if os.environ.get("SOAR_MODE") in ("durable", "ia"):
        file.HUMAIN = cas
    file.travailler(une_fois="--une-fois" in sys.argv, bavard=True)
