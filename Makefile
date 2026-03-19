## ═══════════════════════════════════════════════════════════
##  HuwaControl — Makefile  (Docker uniquement)
##  Déploiement initial : sudo bash deploy.sh
##  Prérequis : Docker + Docker Compose v2
## ═══════════════════════════════════════════════════════════

COMPOSE = docker compose
APP     = huwacontrol_app
DB      = huwacontrol_db

.DEFAULT_GOAL := help

.PHONY: help deploy update setup up down restart build logs logs-app logs-db \
        ps shell-app shell-db db-dump db-restore clean nuke

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

deploy: ## Déploiement complet (installe Docker si absent, génère .env, démarre)
	@bash deploy.sh

update: ## Met à jour le projet (git pull + rebuild + redémarrage)
	@echo "  → Mise à jour du code..."
	@git pull --ff-only 2>/dev/null || echo "  ⚠  Pas de git ou conflits, on rebuild le local"
	$(COMPOSE) up -d --build --remove-orphans
	@echo ""
	@echo "  ✓  Mise à jour terminée"
	@echo ""

setup: ## Copie .env.example → .env et affiche les instructions
	@if [ ! -f .env ]; then \
	  cp .env.example .env; \
	  echo ""; \
	  echo "  ✓  .env créé."; \
	  echo "  →  Éditez .env : changez POSTGRES_PASSWORD et SECRET_KEY"; \
	  echo "  →  Puis lancez : make up"; \
	  echo ""; \
	else \
	  echo "  ✓  .env déjà présent"; \
	fi

up: ## Build et démarrage (première visite → assistant de configuration)
	$(COMPOSE) up -d --build
	@echo ""
	@echo "  ✓  HuwaControl démarré"
	@echo "  →  http://localhost:$${HTTP_PORT:-8080}"
	@echo ""

down: ## Arrêt des services (données conservées)
	$(COMPOSE) down

restart: ## Redémarre l'application
	$(COMPOSE) restart app

build: ## Rebuild l'image sans cache
	$(COMPOSE) build --no-cache app

logs: ## Logs en direct (tous les services)
	$(COMPOSE) logs -f

logs-app: ## Logs application
	$(COMPOSE) logs -f app

logs-db: ## Logs PostgreSQL
	$(COMPOSE) logs -f db

ps: ## État des conteneurs
	$(COMPOSE) ps

shell-app: ## Shell dans le conteneur app
	docker exec -it $(APP) bash

shell-db: ## psql dans PostgreSQL
	docker exec -it $(DB) psql -U $${POSTGRES_USER:-huwa} -d $${POSTGRES_DB:-huwacontrol}

db-dump: ## Sauvegarde → backup.sql
	docker exec $(DB) pg_dump -U $${POSTGRES_USER:-huwa} $${POSTGRES_DB:-huwacontrol} > backup.sql
	@echo "  ✓  backup.sql créé"

db-restore: ## Restaure depuis backup.sql
	@[ -f backup.sql ] || (echo "✗  backup.sql introuvable" && exit 1)
	docker exec -i $(DB) psql -U $${POSTGRES_USER:-huwa} -d $${POSTGRES_DB:-huwacontrol} < backup.sql
	@echo "  ✓  Restauration terminée"

clean: ## Arrête les conteneurs (pg_data conservé)
	$(COMPOSE) down --remove-orphans

nuke: ## ⚠ Supprime TOUT y compris les données PostgreSQL
	@echo "  ⚠  Toutes les données seront supprimées définitivement."
	@read -p "  Confirmer ? [y/N] " ans && [ "$$ans" = "y" ]
	$(COMPOSE) down -v --remove-orphans
	docker image rm huwacontrol-app 2>/dev/null || true
