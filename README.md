<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python" />
  <img src="https://img.shields.io/badge/Flask-3.0-black?logo=flask" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-blue?logo=postgresql" />
  <img src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
</p>

<h1 align="center">HuwaControl</h1>
<p align="center">
  Dashboard de monitoring réseau pour routeurs <strong>Huawei AR Series</strong><br>
  SNMP · Syslog · Ping SLA · Alertes Discord/Telegram · Interface web dark
</p>

---

## Fonctionnalités

| Catégorie | Détail |
|-----------|--------|
| **Dashboard** | CPU, RAM, température, uptime, débit interfaces en temps réel |
| **Interfaces** | Statut, trafic bps/pps, graphiques historiques, alias personnalisés |
| **Syslog** | Réception UDP (RFC 3164/5424), filtrage, pagination, statistiques |
| **Ping / SLA** | Sondes ICMP multi-cibles, SLA %, RTT moyen, historique |
| **SNMP Traps** | Récepteur intégré (SNMPv1/v2c), décodage BER sans dépendances |
| **BGP / OSPF** | État des voisins, uptime, préfixes |
| **Clients** | Table ARP live, historique MAC, DHCP leases |
| **Alertes** | Discord webhooks, Telegram bots, email SMTP |
| **Rapports** | Rapport quotidien automatique (Discord + Telegram) |
| **Sécurité** | Rate limiting login, headers HTTP, session sécurisée |
| **Multi-routeurs** | Gestion de plusieurs routeurs depuis un seul dashboard |

## Prérequis

- **Docker** ≥ 24 + **Docker Compose** v2
- Un routeur Huawei AR Series avec SNMP v2c activé
- Linux recommandé (les ports UDP 514/1162 nécessitent les droits root)

## Installation

```bash
```bash
git clone https://github.com/RealVladilena/huwacontrol.git
cd huwacontrol
docker compose up -d --build
```

Accès : **http://localhost:8080**  
Première connexion → assistant de configuration guidé.

> **Production** : copiez `.env.example` → `.env` et définissez des mots de passe forts avant de démarrer.

## Installation manuelle

```bash
