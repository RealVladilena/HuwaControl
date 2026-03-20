"""
Instance SocketIO partagée — importée par app.py (init_app) et snmp_collector (emit).
Découple l'initialisation de l'application Flask de l'émission d'événements.
"""
from flask_socketio import SocketIO

socketio = SocketIO()
