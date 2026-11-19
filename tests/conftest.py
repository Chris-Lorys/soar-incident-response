"""Fixtures communes : chaque test part d'un environnement neuf (09:20, avant toute réponse)."""
import pytest

from banc import scenario, environnement as env
from minisoar import api, file

CLE_SIEM, CLE_ANALYSTES = "cle-test-siem", "cle-test-analystes"


@pytest.fixture
def alertes(monkeypatch):
    monkeypatch.setenv("SOAR_SECRET_WEBHOOK", CLE_SIEM)
    monkeypatch.setenv("SOAR_SECRET_ANALYSTES", CLE_ANALYSTES)
    monkeypatch.setattr(api, "LANCER", api.lancer)
    monkeypatch.setattr(api, "ROUTAGE", dict(api.ROUTAGE))
    monkeypatch.setattr(file, "HUMAIN", None)
    api.VUES.clear()
    a = scenario.construire()
    env.a_l_heure(a[-1])
    return a
