"""API : authentification des webhooks, normalisation multi-sources, déduplication, routage."""
from fastapi.testclient import TestClient

from banc import scenario
from minisoar import api
from conftest import CLE_SIEM

SIEM = {"x-soar-cle": CLE_SIEM}


def test_webhook_sans_cle_refuse(alertes):
    c = TestClient(api.app)
    assert c.post("/webhooks/siem", json=alertes[0]).status_code == 401
    assert c.post("/webhooks/siem", json=alertes[0], headers={"x-soar-cle": "mauvaise"}).status_code == 401


def test_alerte_malformee_refusee(alertes):
    c = TestClient(api.app)
    r = c.post("/webhooks/siem", json=dict(alertes[5], compte="webadmin; rm -rf /"), headers=SIEM)
    assert r.status_code == 422


def test_routage_et_execution(alertes):
    c = TestClient(api.app)
    r = c.post("/webhooks/siem", json=alertes[0], headers=SIEM).json()
    assert r["playbook"] == "force-brute" and r["statut"] == "terminée"
    etapes = c.get(f"/executions/{r['execution']}").json()["etapes"]
    assert [e["ref"] for e in etapes] == ["cas", "bilan", "bloquer"]


def test_deduplication(alertes):
    c = TestClient(api.app)
    c.post("/webhooks/siem", json=alertes[0], headers=SIEM)
    copie = dict(alertes[0], id="A01-bis", horodatage="2016-12-10T07:28:33")
    assert c.post("/webhooks/siem", json=copie, headers=SIEM).json()["statut"] == "doublon ignoré"


def test_normalisation_wazuh(alertes):
    source, brut = scenario.a_envoyer(alertes[10])
    assert source == "wazuh"
    a = api.normaliser(source, brut)
    assert (a.regle, a.compte, a.hote) == ("R5-cpu", "webadmin", "LabSZ")


def test_normalisation_edr():
    edr = {"alert_id": "edr-5521", "created": "2016-12-10T09:20:00Z",
           "detection": {"name": "Cryptominer", "severity": "high"},
           "device": {"hostname": "LabSZ"},
           "process": {"user": "webadmin", "cmdline": "/tmp/.x/kworkerds -o 198.51.100.9:3333"}}
    a = api.normaliser("edr", edr)
    assert (a.regle, a.niveau, a.compte, a.hote) == ("R5-cpu", 10, "webadmin", "LabSZ")
    assert "kworkerds" in a.description
