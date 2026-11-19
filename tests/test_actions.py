"""Registre d'actions : validation des entrées, garde-fous, idempotence, secrets, réessais."""
import pytest
from pydantic import ValidationError

from banc import environnement as env
from minisoar.actions import action, executer, ErreurTemporaire, SecretManquant


@pytest.mark.parametrize("nom, args", [
    ("pare_feu.bloquer_ip", {"ip": "10.0.0.999"}),
    ("pare_feu.bloquer_ip", {"ip": "1.2.3.4; rm -rf /"}),
    ("hote.tuer_processus", {"pid": 812}),
    ("comptes.desactiver", {"compte": "webadmin && reboot"}),
])
def test_entrees_invalides_refusees_avant_execution(alertes, nom, args):
    with pytest.raises(ValidationError):
        executer(nom, args)
    assert env.audit() == []                      # rien n'a été fait


def test_garde_fou_ip_interne(alertes):
    with pytest.raises(PermissionError):
        executer("pare_feu.bloquer_ip", {"ip": "10.0.0.5"})
    assert "10.0.0.5" not in env.ips_bloquees()


def test_garde_fou_root(alertes):
    with pytest.raises(PermissionError):
        executer("comptes.desactiver", {"compte": "root"})


def test_blocage_idempotent(alertes):
    r1 = executer("pare_feu.bloquer_ip", {"ip": "203.0.113.77"})["result"]
    r2 = executer("pare_feu.bloquer_ip", {"ip": "203.0.113.77"})["result"]
    assert (r1["statut"], r2["statut"]) == ("bloquée", "déjà bloquée")
    assert env.ips_bloquees() == ["203.0.113.77"]


def test_secret_exige_avant_execution(alertes, monkeypatch):
    monkeypatch.delenv("SOAR_SECRET_NTFY", raising=False)
    with pytest.raises(SecretManquant):
        executer("messagerie.notifier", {"titre": "t", "message": "m"})


def test_reessai_seulement_sur_erreur_temporaire(alertes, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    n = {"instable": 0, "logique": 0}

    @action("test.instable")
    def instable() -> dict:
        n["instable"] += 1
        if n["instable"] < 3:
            raise ErreurTemporaire("service occupé")
        return {"ok": True}

    @action("test.logique")
    def logique() -> dict:
        n["logique"] += 1
        raise ValueError("erreur de logique")

    assert executer("test.instable", {}, essais=3)["essais"] == 3
    with pytest.raises(ValueError):
        executer("test.logique", {}, essais=3)
    assert n["logique"] == 1                      # jamais réessayée


def test_bilan_connexions_attaquant(alertes):
    r = executer("journaux.connexions", {"ip": "203.0.113.77"})["result"]
    assert r["premier"].endswith("07:05:12")
    assert r["comptes_entres"] == ["webadmin"]


def test_cles_ssh(alertes):
    r = executer("hote.cles_ssh", {"compte": "webadmin"})["result"]
    assert {c["commentaire"] for c in r["cles"]} == {"deploiement@ci-interne", "attaquant"}


def test_retirer_ligne_refuse_texte_ambigu(alertes):
    with pytest.raises(ValueError):
        executer("hote.retirer_ligne", {"chemin": "home/webadmin/.ssh/authorized_keys", "texte": "AAAA"})
