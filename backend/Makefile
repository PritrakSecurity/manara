.PHONY: build run test clean deps migrate generate

build:
	go build -o bin/dlp-server ./cmd/server

run: build
	./bin/dlp-server

test:
	go test -v ./...

clean:
	rm -rf bin/
	go clean

deps:
	go mod download
	go mod tidy

migrate:
	migrate -path migrations -database "postgres://dlp_user:dlp_pass@localhost/dlp_db?sslmode=disable" up

generate:
	sqlc generate
	protoc --go_out=. --go-grpc_out=. proto/*.proto
