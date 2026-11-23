# infmail-valid-backend — ВАЛИДАТОР сети InfMail (всё в одном)
# См. README.md.
#
#   make build          — собрать (infmail = сеть+почта+API+контракты)
#   make init ROLE=validator — создать конфиг валидатора
#   make run            — запустить
#   make start          — собрать + создать + запустить
#   make tools          — собрать Go/Zig (payouts, watcher, chunkcheck)
#   make status         — статус
#   make clean          — удалить

NODE_DIR ?= ./node-data
VALIDATOR ?= 109.107.155.67:9400

.PHONY: build init run start tools tools-run status clean test

build:
	cargo build --release -p infmail

init:
	./target/release/infnode init --dir $(NODE_DIR) --role validator \
		--validator $(VALIDATOR)

run:
	./target/release/infmail serve --config $(NODE_DIR)/node.yaml

# одна команда для валидатора (нужен INFNODE_VALIDATOR_KEY в env)
start: build init run

# Go/Zig утилиты валидатора: payouts (Distribute TON), watcher (алерты), obs (мониторинг), chunkcheck (аудит чанков)
# Исходники в tools-src/ (в репе) — самодостаточно, без клонирования.
tools:
	@echo "==> Сборка Go/Zig утилит валидатора"
	@mkdir -p tools/bin
	@echo "   Go: payouts"
	@cd tools-src/go && go build -o ../../tools/bin/infmail-payouts ./payouts
	@echo "   Go: watcher"
	@cd tools-src/go && go build -o ../../tools/bin/infmail-watcher ./watcher
	@echo "   Go: obs"
	@cd tools-src/go && go build -o ../../tools/bin/infmail-obs ./obs
	@echo "   Zig: chunkcheck"
	@cd tools-src/zig/cli && zig build-exe infmail-chunkcheck.zig -femit-bin=../../../tools/bin/infmail-chunkcheck
	@echo "==> Готово: tools/bin/*"
	@ls tools/bin/

tools-run:
	@echo "==> Запуск obs на :9100 (фон)"
	@mkdir -p logs
	@INFMAIL_OBS_PORT=127.0.0.1:9100 INFMAIL_OBS_DATA_DIR=$(NODE_DIR) \
		nohup ./tools/bin/infmail-obs > logs/obs.log 2>&1 &
	@sleep 1
	@echo "   obs PID: $$!"

# установить утилиты как постоянные systemd-сервисы (obs, payouts-timer, watcher)
# как на проде валидатора. Требует root. Бинари должны быть в /opt/infnode/bin.
install-tools: tools
	@echo "==> Установка systemd-сервисов утилит (требует root)"
	@sudo mkdir -p /opt/infnode/bin
	@sudo cp tools/bin/infmail-obs tools/bin/infmail-payouts tools/bin/infmail-watcher tools/bin/infmail-chunkcheck /opt/infnode/bin/
	@sudo chmod 755 /opt/infnode/bin/infmail-*
	@sudo cp systemd/infmail-obs.service systemd/infmail-payouts.service systemd/infmail-payouts.timer systemd/infmail-watcher.service /etc/systemd/system/
	@sudo systemctl daemon-reload
	@sudo systemctl enable infmail-obs.service infmail-payouts.timer
	@sudo systemctl restart infmail-obs.service
	@sudo systemctl start infmail-payouts.timer
	@echo "==> Готово: obs :9100, payouts (ежечасно), watcher. Проверка:"
	@curl -s http://127.0.0.1:9100/healthz || echo "   (obs стартует...)"

status:
	./target/release/infnode status --config $(NODE_DIR)/node.yaml

clean:
	rm -rf $(NODE_DIR) tools logs

test:
	cargo test --release -p infmail
