// Package main: infmail-payouts — генератор черновиков Distribute-транзакций TON.
//
// Читает payout_ledger.json валидатора (создан rewards::run в Rust) и для каждой записи
// генерирует черновик транзакции в JSON, который оператор подписывает в своём vault/мультисиге.
//
// Принципы:
//   - Приватный ключ payout НЕ хранится в этом процессе (per рекомендации безопасности).
//   - Оператор сам подписывает транзакции в TON-wallet и шлёт в сеть.
//   - Этот сервис — только генератор payload (адрес получателя + сумма + комментарий).
//
// Использование:
//   INFMAIL_DATA_DIR=/opt/infnode \
//   INFMAIL_PAYOUT_ADDRESS=EQB... (адрес payout-кошелька валидатора) \
//   ./infmail-payouts                       # все pending payouts
//   ./infmail-payouts --status=pending      # только pending
//   ./infmail-payouts --last=5              # последние 5
//   ./infmail-payouts --dry-run             # без вывода файлов
//
// Формат черновика (distribute-{ts}.json):
//   {
//     "ts": 1234567890000,
//     "to": "EQB...",                    // адрес получателя (нода)
//     "amount_nt": 1000000,              // в нанотонах
//     "amount_ton": 0.001,
//     "comment": "INFMAIL_PAYOUT:{node_id}:{ts}",
//     "from": "EQB_Y-...",                // payout-адрес валидатора (отправитель)
//     "ledger_entry": {...}              // ссылка на ledger-запись
//   }
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type payoutEntry struct {
	NodeID   string  `json:"node_id"`
	Name     string  `json:"name"`
	Weight   float64 `json:"weight"`
	ShareNT  int64   `json:"share_nt"`
	ShareTON float64 `json:"share_ton"`
	Status   string  `json:"status"`
}

type ledgerEntry struct {
	TS          int64         `json:"ts"`
	PoolTON     float64       `json:"pool_ton"`
	TotalWeight float64       `json:"total_weight"`
	Payouts     []payoutEntry `json:"payouts"`
}

type distributeTx struct {
	TS         int64         `json:"ts"`
	To         string        `json:"to"`
	AmountNT   int64         `json:"amount_nt"`
	AmountTON  float64       `json:"amount_ton"`
	Comment    string        `json:"comment"`
	From       string        `json:"from"`
	LedgerRef  ledgerEntry   `json:"ledger_entry_ref"`
}

func loadLedger(path string) ([]ledgerEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var arr []ledgerEntry
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

func loadNodeWallets(dataDir string) (map[string]string, error) {
	// Пытаемся найти адреса нод в kv.json (ключ user:{node_id} — публичные ключи)
	// и в отдельном файле node_wallets.json (если есть).
	wp := filepath.Join(dataDir, "node_wallets.json")
	if b, err := os.ReadFile(wp); err == nil {
		var m map[string]string
		if err := json.Unmarshal(b, &m); err == nil {
			return m, nil
		}
	}
	return map[string]string{}, nil
}

func main() {
	dataDir := os.Getenv("INFMAIL_DATA_DIR")
	if dataDir == "" {
		dataDir = "/opt/infnode"
	}
	payoutAddr := os.Getenv("INFMAIL_PAYOUT_ADDRESS")
	if payoutAddr == "" {
		payoutAddr = "EQB_PAYOUT_ADDRESS_NOT_SET"
	}

	statusFilter := flag.String("status", "", "filter by status (pending/done/all)")
	last := flag.Int("last", 0, "process only last N entries (0 = all)")
	dryRun := flag.Bool("dry-run", false, "don't write files, just print")
	outputDir := flag.String("out", filepath.Join(dataDir, "distribute_drafts"), "output directory for tx drafts")
	flag.Parse()

	ledgerPath := filepath.Join(dataDir, "payout_ledger.json")
	ledger, err := loadLedger(ledgerPath)
	if err != nil {
		log.Fatalf("не удалось прочитать %s: %v", ledgerPath, err)
	}
	log.Printf("загружено %d ledger-записей", len(ledger))

	wallets, _ := loadNodeWallets(dataDir)
	log.Printf("найдено %d node_wallets", len(wallets))

	// Сортируем по TS (новые сверху)
	sort.Slice(ledger, func(i, j int) bool {
		return ledger[i].TS > ledger[j].TS
	})
	if *last > 0 && *last < len(ledger) {
		ledger = ledger[:*last]
	}

	if !*dryRun {
		if err := os.MkdirAll(*outputDir, 0o755); err != nil {
			log.Fatalf("не удалось создать %s: %v", *outputDir, err)
		}
	}

	totalTxs := 0
	totalTON := 0.0
	for _, e := range ledger {
		for _, p := range e.Payouts {
			if *statusFilter != "" && *statusFilter != "all" && p.Status != *statusFilter {
				continue
			}
			addr, ok := wallets[p.NodeID]
			if !ok || addr == "" {
				log.Printf("ПРОПУСК: для ноды %s (payout share=%.6f TON) нет кошелька в node_wallets.json", p.NodeID, p.ShareTON)
				continue
			}
			tx := distributeTx{
				TS:        e.TS,
				To:        addr,
				AmountNT:  p.ShareNT,
				AmountTON: p.ShareTON,
				Comment:   fmt.Sprintf("INFMAIL_PAYOUT:%s:%d", p.NodeID, e.TS),
				From:      payoutAddr,
				LedgerRef: e,
			}
			totalTxs++
			totalTON += p.ShareTON
			if *dryRun {
				b, _ := json.MarshalIndent(tx, "", "  ")
				fmt.Println(string(b))
			} else {
				fn := filepath.Join(*outputDir, fmt.Sprintf("distribute-%d-%s.json", e.TS, p.Name))
				b, _ := json.MarshalIndent(tx, "", "  ")
				if err := os.WriteFile(fn, b, 0o644); err != nil {
					log.Printf("ошибка записи %s: %v", fn, err)
				} else {
					log.Printf("создан черновик: %s (%.6f TON → %s)", fn, p.ShareTON, addr)
				}
			}
		}
	}

	log.Printf("итого: %d черновиков, %.6f TON (dir=%s)", totalTxs, totalTON, *outputDir)
	if !*dryRun {
		log.Printf("оператор: подпишите черновики в TON-wallet и отправьте в сеть")
		log.Printf("         (Tonkeeper/MultisigWallet/TON-cli принимают ручную отправку)")
	}

	// Подавим неиспользуемый импорт, если флаг --status=all без фильтра
	_ = strings.TrimSpace
	_ = time.Now
}