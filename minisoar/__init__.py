"""Plateforme SOAR en Python, inspiré de Tracecat."""
# Charger un module enregistre ses actions : on charge toutes les intégrations dès l'import du paquet,
# pour que le registre soit complet quel que soit le module importé en premier.
from . import actions, cas  # noqa: F401

try:
    from . import ia  # noqa: F401  (ai.action, ai.agent : nécessite langchain)
except ImportError:
    pass
