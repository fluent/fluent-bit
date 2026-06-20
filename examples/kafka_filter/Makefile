build:
	docker compose build

start:
	docker compose up -d
	docker compose logs -f fluent-bit kafka-consumer

stop:
	docker compose down

.PHONY: build start stop
