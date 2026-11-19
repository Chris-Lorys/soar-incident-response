"""File durable : réservation atomique, reprise après panne, annulation."""
import os, subprocess, sys, time
from pathlib import Path

from fastapi.testclient import TestClient

from banc import environnement as env
from minisoar import api, file
from conftest import CLE_SIEM, CLE_ANALYSTES

RACINE = Path(__file__).resolve().parent.parent


def test_annulation(alertes):
    id_ = file.deposer("force-brute", alertes[0])
    assert file.annuler(id_) is True
    assert file.prendre("test") is None
    assert file.etat(id_)["statut"] == "annulée"
    assert file.annuler(id_) is False


def test_route_annulation_reservee_aux_analystes(alertes):
    c = TestClient(api.app)
    id_ = file.deposer("force-brute", alertes[0])
    assert c.post(f"/executions/{id_}/annuler", headers={"x-soar-cle": CLE_SIEM}).status_code == 401
    assert c.post(f"/executions/{id_}/annuler", headers={"x-soar-cle": CLE_ANALYSTES}).status_code == 200
    assert c.post(f"/executions/{id_}/annuler", headers={"x-soar-cle": CLE_ANALYSTES}).status_code == 409


def test_reprise_apres_panne_sans_double_effet(alertes, monkeypatch):
    monkeypatch.setattr(api, "LANCER", api.lancer_en_file)
    c = TestClient(api.app)
    env.a_l_heure(alertes[5])
    r = c.post("/webhooks/siem", json=alertes[5], headers={"x-soar-cle": CLE_SIEM}).json()

    # Un travailleur plante juste APRÈS avoir bloqué l'IP, AVANT d'avoir enregistré l'étape.
    variables = dict(os.environ, SOAR_PANNE_APRES="bloquer", SOAR_BAIL="1")
    p = subprocess.run([sys.executable, "-m", "minisoar.travailleur", "--une-fois"], cwd=RACINE, env=variables,
                       capture_output=True, text=True)
    assert p.returncode == 1
    assert "203.0.113.77" in env.ips_bloquees()
    assert "bloquer" not in [e["ref"] for e in file.etat(r["execution"])["etapes"]]

    time.sleep(1.2)                               # le bail expire : l'exécution est orpheline
    assert file.travailler(une_fois=True, travailleur="relève") == 1
    etat = file.etat(r["execution"])
    assert etat["statut"] == "terminée" and etat["travailleur"] == "relève"
    assert env.ips_bloquees() == ["203.0.113.77"]          # au moins une fois, mais idempotent
    blocages = [a["resultat"] for a in env.audit() if a["action"] == "bloquer_ip"]
    assert blocages == ["bloquée", "déjà bloquée"]
