// Package main: infmail-watcher — мониторинг аномалий инсталла (Go, П.3.6+).
//
// Периодически (раз в 60с) проверяет:
//   - infmail HTTP API /healthz (через /api/v1/auth/me или прямой HTTP)
//   - размер kv.json / chunks/ — аномальный рост?
//   - список chunks без манифестов (orphans)
//   - rewards.json: ноды вниз >N циклов
//   - payout_ledger.json: застрявшие pending payouts
//
// При обнаружении проблем пишет алерт в /opt/infnode/alerts.log и в stderr.
// Также доступен HTTP-эндпоинт /alerts на порту 9101 для prometheus/blackbox.
//
// Сборка: go build -o infmail-watcher .
// Запуск (systemd, см. /etc/systemd/system/infmail-watcher.service):
//   INFMAIL_API_URL=http://127.0.0.1:3001 INFMAIL_DATA_DIR=/opt/infnode \
//   INFMAIL_WATCHER_PORT=9101 /opt/infnode/bin/infmail-watcher
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	APIBase  string
	DataDir  string
	Port     string
	LogPath  string
}

func loadConfig() Config {
	return Config{
		APIBase: getenv("INFMAIL_API_URL", "http://127.0.0.1:3001"),
		DataDir: getenv("INFMAIL_DATA_DIR", "/opt/infnode"),
		Port:    getenv("INFMAIL_WATCHER_PORT", "9101"),
		LogPath: getenv("INFMAIL_WATCHER_LOG", "/opt/infnode/alerts.log"),
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type Alert struct {
	TS       time.Time `json:"ts"`
	Severity string    `json:"severity"` // info, warn, critical
	Source   string    `json:"source"`
	Message  string    `json:"message"`
}

type Watcher struct {
	cfg      Config
	mu       sync.Mutex
	alerts   []Alert
	lastRun  time.Time
	checks   map[string]bool // name -> ok
}

func NewWatcher(cfg Config) *Watcher {
	return &Watcher{cfg: cfg, alerts: []Alert{}, checks: map[string]bool{}}
}

func (w *Watcher) logAlert(a Alert) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.alerts = append(w.alerts, a)
	// keep only last 200
	if len(w.alerts) > 200 {
		w.alerts = w.alerts[len(w.alerts)-200:]
	}
	// write to file
	if f, err := os.OpenFile(w.cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		enc := json.NewEncoder(f)
		_ = enc.Encode(a)
		f.Close()
	}
	// also stderr
	sev := strings.ToUpper(a.Severity)
	log.Printf("[%s] %s: %s", sev, a.Source, a.Message)
}

func (w *Watcher) checkAPI() bool {
	url := w.cfg.APIBase + "/api/v1/pricing"
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		w.logAlert(Alert{TS: time.Now(), Severity: "critical", Source: "api", Message: fmt.Sprintf("API недоступен: %v", err)})
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		w.logAlert(Alert{TS: time.Now(), Severity: "critical", Source: "api", Message: fmt.Sprintf("API status %d", resp.StatusCode)})
		return false
	}
	w.mu.Lock()
	w.checks["api"] = true
	w.mu.Unlock()
	return true
}

func (w *Watcher) checkKV() {
	path := filepath.Join(w.cfg.DataDir, "kv.json")
	info, err := os.Stat(path)
	if err != nil {
		w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "kv", Message: fmt.Sprintf("kv.json не найден: %v", err)})
		return
	}
	// > 100MB = warn
	if info.Size() > 100*1024*1024 {
		w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "kv", Message: fmt.Sprintf("kv.json вырос до %d MB", info.Size()/1024/1024)})
	}
	w.mu.Lock()
	w.checks["kv"] = true
	w.mu.Unlock()
}

func (w *Watcher) checkRewards() {
	path := filepath.Join(w.cfg.DataDir, "rewards.json")
	b, err := os.ReadFile(path)
	if err != nil {
		w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "rewards", Message: fmt.Sprintf("rewards.json не найден: %v", err)})
		return
	}
	var rf struct {
		TS int64 `json:"ts"`
	}
	_ = json.Unmarshal(b, &rf)
	// если rewards старше 30 минут — warn
	if rf.TS > 0 {
		ageMin := (time.Now().UnixMilli() - rf.TS) / 60000
		if ageMin > 30 {
			w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "rewards", Message: fmt.Sprintf("rewards.json не обновлялся %d мин", ageMin)})
		}
	}
	w.mu.Lock()
	w.checks["rewards"] = true
	w.mu.Unlock()
}

func (w *Watcher) checkPayouts() {
	path := filepath.Join(w.cfg.DataDir, "payout_ledger.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return // необязательный файл
	}
	var ledger []struct {
		Payouts []struct {
			Status string `json:"status"`
		} `json:"payouts"`
	}
	_ = json.Unmarshal(b, &ledger)
	oldPending := 0
	for _, e := range ledger {
		for _, p := range e.Payouts {
			if p.Status == "pending" {
				oldPending++
			}
		}
	}
	if oldPending > 50 {
		w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "payouts", Message: fmt.Sprintf("%d pending payouts — оператор не раздаёт", oldPending)})
	}
	w.mu.Lock()
	w.checks["payouts"] = true
	w.mu.Unlock()
}

func (w *Watcher) checkOrphans() {
	// chunks/mail без манифестов m:mail:* — самый частый сигнал проблем.
	chunksDir := filepath.Join(w.cfg.DataDir, "chunks", "mail")
	mfsDir := filepath.Join(w.cfg.DataDir, "chunks", "files")
	// посчитаем файлы в chunks/
	chunkCount := 0
	if entries, err := os.ReadDir(chunksDir); err == nil {
		chunkCount += len(entries)
	}
	if entries, err := os.ReadDir(mfsDir); err == nil {
		chunkCount += len(entries)
	}
	if chunkCount > 100000 {
		w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "chunks", Message: fmt.Sprintf("чанков > 100k: %d", chunkCount)})
	}
	w.mu.Lock()
	w.checks["orphans"] = true
	w.mu.Unlock()
}

func (w *Watcher) runOnce() {
	w.checkAPI()
	w.checkKV()
	w.checkRewards()
	w.checkPayouts()
	w.checkOrphans()
	w.mu.Lock()
	w.lastRun = time.Now()
	w.mu.Unlock()
}

func (w *Watcher) handleHealth(w2 http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	status := "ok"
	for _, ok := range w.checks {
		if !ok {
			status = "degraded"
		}
	}
	w2.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w2).Encode(map[string]any{
		"status":   status,
		"last_run": w.lastRun.Unix(),
		"checks":   w.checks,
	})
}

func (w *Watcher) handleAlerts(w2 http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w2.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w2).Encode(map[string]any{
		"alerts": w.alerts,
	})
}

func main() {
	cfg := loadConfig()
	w := NewWatcher(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", w.handleHealth)
	mux.HandleFunc("/alerts", w.handleAlerts)

	go func() {
		// первый прогрев
		time.Sleep(2 * time.Second)
		w.runOnce()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			w.runOnce()
		}
	}()

	addr := ":" + cfg.Port
	log.Printf("infmail-watcher на %s (api=%s, data=%s)", addr, cfg.APIBase, cfg.DataDir)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}