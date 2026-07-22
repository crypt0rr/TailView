.PHONY: install lint test build compose-check up down backup restore verify-backup
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
