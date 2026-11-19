"""Cas et humain dans la boucle : rattachement, fusion, approbations, rejeu complet."""
from fastapi.testclient import TestClient

from banc import environnement as env, scenario
from minisoar import api, file, cas
from conftest import CLE_SIEM, CLE_ANALYSTES

SIEM, ANALYSTE = {"x-soar-cle": CLE_SIEM}, {"x-soar-cle": CLE_ANALYSTES}


def _mode_complet(monkeypatch):
    monkeypatch.setattr(api, "LANCER", api.lancer_en_file)
    monkeypatch.setattr(file, "HUMAIN", cas)
    api.ROUTAGE.update({"R2-succes-apres-echecs": "connexion-suspecte-cas", "R3-compte-leurre": "connexion-suspecte-cas",
                        "R4-sortant-suspect": "activite-hote-cas", "R5-cpu": "activite-hote-cas"})
    return TestClient(api.app)


def _recevoir(c, alerte):
    env.a_l_heure(alerte)
    source, brut = scenario.a_envoyer(alerte)
    r = c.post(f"/webhooks/{source}", json=brut, headers=SIEM).json()
    file.travailler(une_fois=True, travailleur="test")
    return r


def test_approbation_humaine(alertes, monkeypatch):
    c = _mode_complet(monkeypatch)
    r = _recevoir(c, alertes[5])
    assert file.etat(r["execution"])["statut"] == "en attente"
    assert env.comptes()["webadmin"]["actif"]                     # pas encore désactivé
    assert c.get("/approbations", headers=SIEM).status_code == 401  # le SIEM ne décide pas

    d = c.get("/approbations", headers=ANALYSTE).json()[0]
    assert d["action"] == "comptes.desactiver"
    c.post(f"/approbations/{d['execution']}/{d['ref']}", headers=ANALYSTE,
           json={"decision": "approuver", "analyste": "analyste-garde", "apres_minutes": 12})
    file.travailler(une_fois=True, travailleur="test")
    assert file.etat(r["execution"])["statut"] == "terminée"
    assert not env.comptes()["webadmin"]["actif"]


def test_refus_humain(alertes, monkeypatch):
    c = _mode_complet(monkeypatch)
    r = _recevoir(c, alertes[5])
    d = c.get("/approbations", headers=ANALYSTE).json()[0]
    c.post(f"/approbations/{d['execution']}/{d['ref']}", headers=ANALYSTE,
           json={"decision": "refuser", "analyste": "analyste-garde"})
    file.travailler(une_fois=True, travailleur="test")
    assert file.etat(r["execution"])["statut"] == "terminée"
    assert env.comptes()["webadmin"]["actif"]


def test_rejeu_complet_relie_les_alertes(alertes, monkeypatch):
    c = _mode_complet(monkeypatch)
    for a in alertes:
        _recevoir(c, a)
        for d in c.get("/approbations", headers=ANALYSTE).json():
            c.post(f"/approbations/{d['execution']}/{d['ref']}", headers=ANALYSTE,
                   json={"decision": "approuver", "analyste": "analyste-garde", "apres_minutes": 12})
            file.travailler(une_fois=True, travailleur="test")
    t = cas.tableau()
    principal = t.sort_values("alertes").iloc[-1]
    assert principal["alertes"] == 4 and principal["severite"] == "critique"
    robots = t[t.titre.str.startswith("5 échecs SSH")]
    assert len(robots) >= 6 and (robots.statut == "fermé").all()   # les robots sont fermés automatiquement
    assert "fusion" in cas.rapport(principal["id"])
