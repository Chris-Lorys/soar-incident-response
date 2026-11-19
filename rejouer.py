"""Rejoue la matinée d'alertes du 10 décembre 2016 dans le SOAR, de bout en bout, et le note sur 100.

    python rejouer.py                 # file durable + cas + approbations (sans IA)
    python rejouer.py --mode simple   # API synchrone + playbooks déterministes
    python rejouer.py --mode ia       # + étape IA (nécessite Ollama et le modèle SOAR_MODELE)

Chaque alerte part par HTTP vers le webhook de son outil (SIEM ou Wazuh, chacun dans son format),
exactement comme en production. Un analyste simulé approuve les actions sensibles.
Résultats : dossier resultats/ (rapport Markdown + scores.csv) ; effets : dossier environnement/.
"""
import argparse, os

from fastapi.testclient import TestClient

from banc import scenario, rejeu
from minisoar import api, file, cas

CLE_SIEM, CLE_ANALYSTES = "cle-demo-siem", "cle-demo-analystes"


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--mode", choices=["simple", "complet", "ia"], default="complet")
    p.add_argument("--delai-analyste", type=float, default=12, help="minutes avant chaque approbation simulée")
    args = p.parse_args()
    mode, delai = args.mode, args.delai_analyste

    os.environ.setdefault("SOAR_SECRET_WEBHOOK", CLE_SIEM)
    os.environ.setdefault("SOAR_SECRET_ANALYSTES", CLE_ANALYSTES)
    siem = {"x-soar-cle": os.environ["SOAR_SECRET_WEBHOOK"]}
    analyste = {"x-soar-cle": os.environ["SOAR_SECRET_ANALYSTES"]}
    soar = TestClient(api.app)
    scenario.construire()
    api.VUES.clear()

    if mode != "simple":
        api.mode_durable(ia=mode == "ia")

    def envoyer(alerte):
        source, brut = scenario.a_envoyer(alerte)
        r = soar.post(f"/webhooks/{source}", json=brut, headers=siem).json()
        if mode == "simple":
            sortie = r.get("sortie") or {}
        else:
            file.travailler(une_fois=True, travailleur="travailleur-1")
            while demandes := soar.get("/approbations", headers=analyste).json():     # analyste simulé
                for d in demandes:
                    print(f"   ✋ approuvé : {d['action']} {d['args'][:90]}")
                    soar.post(f"/approbations/{d['execution']}/{d['ref']}", headers=analyste,
                              json={"decision": "approuver", "analyste": "analyste-garde", "apres_minutes": delai})
                file.travailler(une_fois=True, travailleur="travailleur-1")
            sortie = (file.etat(r["execution"]) or {}).get("sortie") or {} if "execution" in r else {}
        return f"{sortie.get('rapport', r)}\nVERDICT : {sortie.get('verdict', '?')}"

    def rapport_final():
        t = cas.tableau()
        return cas.rapport(t.sort_values("alertes").iloc[-1]["id"])

    rejeu.rejouer(envoyer, f"rejeu-{mode}", synthese=None if mode == "simple" else rapport_final)
    if mode != "simple":
        print("\nCas ouverts pendant la matinée :")
        print(cas.tableau().to_string(index=False))


if __name__ == "__main__":
    main()
