"""
Modèles applicatifs partagés (User pour Flask-Login).
"""
from flask_login import UserMixin


class User(UserMixin):
    def __init__(self, data: dict):
        self.id       = str(data["id"])
        self.username = data["username"]
        self.is_admin = data["is_admin"]
