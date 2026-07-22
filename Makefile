.PHONY: install lint test build compose-check up down backup restore verify-backup soak-start soak-login soak-check soak-restart soak-finish
install:
	cd frontend && npm ci
build:
	cd frontend && npm run build
	docker build -t tailview-backend:test backend
lint:
	cd frontend && npm run lint
	docker run --rm -v "$(CURDIR)/backend:/app" -w /app python:3.13.14-slim sh -c "pip install -q '.[dev]' && ruff check app tests && mypy app"
test:
	cd frontend && npm test
	docker run --rm -v "$(CURDIR)/backend:/app" -w /app python:3.13.14-slim sh -c "pip install -q '.[dev]' && PYTHONPATH=/app pytest --cov=app"
compose-check:
	docker compose --env-file .env.example config --quiet
up:
	docker compose up -d --build
down:
	docker compose down
backup:
	sh deploy/backup.sh
restore:
	@test -n "$(FILE)" || (echo "Usage: make restore FILE=tailview.dump" && exit 2)
	sh deploy/restore.sh "$(FILE)"
verify-backup:
	@test -n "$(FILE)" || (echo "Usage: make verify-backup FILE=tailview.dump" && exit 2)
	sh deploy/verify-backup.sh "$(FILE)"
soak-start:
	@test -n "$(CANDIDATE)" || (echo "Usage: make soak-start CANDIDATE=v1.0.0-rc.1 BACKUP=/absolute/path/tailview.dump ENV_FILE=.env.soak" && exit 2)
	@test -n "$(BACKUP)" || (echo "BACKUP is required" && exit 2)
	CANDIDATE_TAG="$(CANDIDATE)" BACKUP_FILE="$(BACKUP)" SOAK_ENV_FILE="$(or $(ENV_FILE),.env.soak)" sh deploy/soak-start.sh
soak-login:
	@test -n "$(CANDIDATE)" || (echo "CANDIDATE is required" && exit 2)
	@test -n "$(USERNAME)" || (echo "USERNAME is required" && exit 2)
	CANDIDATE_TAG="$(CANDIDATE)" SOAK_USERNAME="$(USERNAME)" SOAK_ENV_FILE="$(or $(ENV_FILE),.env.soak)" sh deploy/soak-login.sh
soak-check:
	@test -n "$(CANDIDATE)" || (echo "CANDIDATE is required" && exit 2)
	CANDIDATE_TAG="$(CANDIDATE)" SOAK_ENV_FILE="$(or $(ENV_FILE),.env.soak)" sh deploy/soak-check.sh
soak-restart:
	@test -n "$(CANDIDATE)" || (echo "CANDIDATE is required" && exit 2)
	CANDIDATE_TAG="$(CANDIDATE)" SOAK_ENV_FILE="$(or $(ENV_FILE),.env.soak)" sh deploy/soak-restart.sh
soak-finish:
	@test -n "$(CANDIDATE)" || (echo "CANDIDATE is required" && exit 2)
	CANDIDATE_TAG="$(CANDIDATE)" SOAK_ENV_FILE="$(or $(ENV_FILE),.env.soak)" \
		RELEASE_GPG_FINGERPRINT="$(GPG_FINGERPRINT)" SOAK_UPLOAD="$(or $(UPLOAD),false)" sh deploy/soak-finish.sh
