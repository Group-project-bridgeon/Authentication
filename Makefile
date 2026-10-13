MAIN := ./cmd/server
MIGRATE ?= migrate
MIGRATIONS_PATH ?= ./db/migrations
DATABASE_URL ?= postgres://postgres:postgres@localhost:5432/auth?sslmode=disable

.PHONY: run build docker-up docker-down migrate-up migrate-version test

run:
	go run $(MAIN)

build:
	go build -o bin/server $(MAIN)

docker-up:
	docker compose up -d

docker-down:
	docker compose down

migrate-up:
	$(MIGRATE) -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" up

migrate-version:
	$(MIGRATE) -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" version

test:
	go test -v ./...
