SHELL := /bin/bash

.PHONY: help build run vet test compose-up compose-down compose-logs e2e clean

help:
	@echo "Targets:"
	@echo "  build          - 编译 oneauth-server 二进制"
	@echo "  run            - 本地直接 go run（需要先有 mysql/redis）"
	@echo "  vet            - go vet 静态检查"
	@echo "  compose-up     - 启动 docker-compose（mysql+redis+migrate+server）"
	@echo "  compose-down   - 停止并删除容器（保留 volume）"
	@echo "  compose-logs   - 看 oneauth 日志"
	@echo "  e2e            - 跑 e2e 测试脚本（需先 compose-up）"
	@echo "  clean          - 清理编译产物"

build:
	cd server && go build -o bin/oneauth-server ./cmd/server

run: build
	cd server && ./bin/oneauth-server -config config/config.yaml

vet:
	cd server && go vet ./...

test:
	cd server && go test ./... -count=1

compose-up:
	@if [ ! -f deploy/docker-compose/.env ]; then \
		echo "==> creating .env from .env.example"; \
		cp deploy/docker-compose/.env.example deploy/docker-compose/.env; \
		echo "==> EDIT deploy/docker-compose/.env to set real passwords"; \
	fi
	cd deploy/docker-compose && docker compose up -d --build

compose-down:
	cd deploy/docker-compose && docker compose down

compose-down-clean:
	cd deploy/docker-compose && docker compose down -v

compose-logs:
	cd deploy/docker-compose && docker compose logs -f oneauth

compose-ps:
	cd deploy/docker-compose && docker compose ps

e2e:
	bash server/scripts/test_e2e.sh

clean:
	rm -rf server/bin server/keys/*.pem
