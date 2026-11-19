"""Moteur de workflow : expressions sans eval(), validation des playbooks, exécution."""
import pytest

from banc import environnement as env
from minisoar import moteur

CTX = {"TRIGGER": {"ip": "203.0.113.77"},
       "ACTIONS": {"bilan": {"result": {"echecs": 21, "comptes_entres": ["webadmin"]}}}}


def test_expressions_gardent_le_type():
    assert moteur.evaluer("${{ TRIGGER.ip }}", CTX) == "203.0.113.77"
    assert moteur.evaluer("${{ ACTIONS.bilan.result.echecs > 5 && FN.length(ACTIONS.bilan.result.comptes_entres) > 0 }}", CTX) is True
    assert moteur.evaluer("IP ${{ TRIGGER.ip }} sur ${{ ACTIONS.bilan.result.comptes_entres[0] }}", CTX) == "IP 203.0.113.77 sur webadmin"
    assert moteur.evaluer("${{ ACTIONS.bilan.result.absent }}", CTX) is None


@pytest.mark.parametrize("code", [
    "${{ __import__('os').system('id') }}",
    "${{ TRIGGER.__class__.__mro__ }}",
    "${{ open('/etc/passwd').read() }}",
    "${{ [x for x in TRIGGER] }}",
])
def test_injection_de_gabarit_refusee(code):
    with pytest.raises(moteur.ExpressionInterdite):
        moteur.evaluer(code, CTX)


@pytest.mark.parametrize("playbook", [
    {"actions": [{"ref": "a", "action": "pare_feu.tout_bloquer"}]},
    {"actions": [{"ref": "a", "action": "hote.processus", "depends_on": ["b"]},
                 {"ref": "b", "action": "hote.processus", "depends_on": ["a"]}]},
    {"actions": [{"ref": "Bloquer IP", "action": "pare_feu.bloquer_ip"}]},
])
def test_playbook_invalide_refuse_au_chargement(playbook):
    with pytest.raises(moteur.PlaybookInvalide):
        moteur.valider(playbook)


@pytest.mark.parametrize("nom", ["connexion-suspecte", "connexion-suspecte-cas", "activite-hote",
                                 "activite-hote-cas", "activite-hote-ia", "force-brute"])
def test_tous_les_playbooks_sont_valides(nom):
    assert moteur.charger(nom).etapes


def test_intrusion_confinee(alertes):
    a = alertes[5]                                # A06, 08:41 : l'attaquant entre sur webadmin
    env.a_l_heure(a)
    ex = moteur.executer(moteur.charger("connexion-suspecte"), a)
    assert ex.sortie["verdict"] == "incident"
    assert "07:05" in ex.sortie["rapport"]
    assert "203.0.113.77" in env.ips_bloquees() and not env.comptes()["webadmin"]["actif"]


def test_faux_positif_admin_interne(alertes):
    a = alertes[2]                                # A03, 08:02 : l'admin se trompe de mot de passe
    env.a_l_heure(a)
    ex = moteur.executer(moteur.charger("connexion-suspecte"), a)
    assert ex.sortie["verdict"] == "faux positif"
    assert ex.historique["bloquer"]["statut"] == "ignorée"
    assert env.ips_bloquees() == [] and env.comptes()["jtremblay"]["actif"]


def test_force_brute_robot_et_attaquant(alertes):
    pb = moteur.charger("force-brute")
    robot = alertes[0]
    attaquant = dict(robot, ip="203.0.113.77", horodatage="2016-12-10T09:00:00")
    env.a_l_heure(robot)
    r1 = moteur.executer(pb, robot)
    env.a_l_heure(attaquant)
    r2 = moteur.executer(pb, attaquant)
    assert r1.sortie["verdict"] == "attaque sans impact" and r1.historique["bloquer"]["statut"] == "réussie"
    assert r2.sortie["verdict"] == "incident" and r2.historique["bloquer"]["statut"] == "ignorée"
