"""Étape IA, avec un faux modèle : sortie contrainte par schéma, liste blanche de l'agent."""
import json

import pytest
from langchain_core.messages import AIMessage

from minisoar import ia
from minisoar.actions import executer


class FauxModele:
    def __init__(self, reponses):
        self.reponses = list(reponses)

    def bind_tools(self, outils):
        return self

    def invoke(self, messages):
        return self.reponses.pop(0)


SCHEMA = {"type": "object", "properties": {"cle": {"type": "string"}}, "required": ["cle"]}


def test_ai_action_sortie_conforme(alertes, monkeypatch):
    monkeypatch.setattr(ia, "LLM", FauxModele([AIMessage(json.dumps({"cle": "attaquant"}))]))
    assert executer("ai.action", {"consigne": "c", "donnees": {}, "sortie": SCHEMA})["result"] == {"cle": "attaquant"}


def test_ai_action_champ_manquant(alertes, monkeypatch):
    monkeypatch.setattr(ia, "LLM", FauxModele([AIMessage(json.dumps({"autre": 1}))]))
    with pytest.raises(ValueError):
        executer("ai.action", {"consigne": "c", "donnees": {}, "sortie": SCHEMA})


def test_ai_agent_liste_blanche(alertes):
    with pytest.raises(PermissionError):
        executer("ai.agent", {"consigne": "c", "demande": "d", "actions": ["pare_feu.inexistante"]})
    with pytest.raises(PermissionError):
        executer("ai.agent", {"consigne": "c", "demande": "d", "actions": ["ai.agent"]})


def test_ai_agent_appelle_ses_outils_et_borne_la_boucle(alertes, monkeypatch):
    appel = AIMessage("", tool_calls=[{"name": "journaux__connexions", "args": {"ip": "203.0.113.77"}, "id": "1"}])
    monkeypatch.setattr(ia, "LLM", FauxModele([appel, AIMessage("webadmin compromis depuis 203.0.113.77")]))
    r = executer("ai.agent", {"consigne": "c", "demande": "d", "actions": ["journaux.connexions"]})["result"]
    assert r["appels"][0]["action"] == "journaux.connexions"
    assert "203.0.113.77" in r["reponse"]

    monkeypatch.setattr(ia, "LLM", FauxModele([appel] * 3))
    r = executer("ai.agent", {"consigne": "c", "demande": "d", "actions": ["journaux.connexions"], "max_appels": 2})["result"]
    assert r["reponse"].startswith("Arrêt") and len(r["appels"]) == 2
