MAIN := ./cmd/server

.PHONY: run build docker-up docker-down migrate-up test

run:
	go run $(MAIN)

build:
	go build -o bin/server $(MAIN)

docker-up:
	docker compose up -d

docker-down:
	docker compose down

migrate-up:
	docker compose exec -T postgres psql -U postgres -d auth < db/migrations/000001_create_users.up.sql
	docker compose exec -T postgres psql -U postgres -d auth < db/migrations/000002_add_email_verification.up.sql

test:
	go test -v ./...