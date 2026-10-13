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
	for f in $$(ls db/migrations/*.up.sql | sort); do \
		echo "Applying $$f..."; \
		docker compose exec -T postgres psql -U postgres -d auth < $$f || exit 1; \
	done
test:
	go test -v ./...