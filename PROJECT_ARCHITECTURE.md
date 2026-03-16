# VaultVision — Архитектура проекта

> Техническая документация. Как всё устроено внутри.
> Обновлено: март 2026

---

## Обзор системы

```
┌──────────────────────────────────────────────────────────────────┐
│                     VAULTVISION ARCHITECTURE                      │
│                                                                    │
│  ┌─────────────┐     ┌──────────────┐     ┌─────────────────┐   │
│  │  Hyperliquid │     │   back.py     │     │  Frontend       │   │
│  │  APIs        │────→│   (8500 LOC)  │────→│  (4000 LOC)     │   │
│  │              │     │               │     │  Single HTML    │   │
│  │ stats-data   │     │  HTTP Server  │     │  SPA            │   │
│  │ api.hl.xyz   │     │  port 8787    │     │                 │   │
│  └─────────────┘     └──────┬───────┘     └─────────────────┘   │
│                              │                                     │
│                        ┌─────┴─────┐                              │
│                        │  SQLite    │                              │
│                        │  WAL mode  │                              │
│                        │  12 tables │                              │
│                        └───────────┘                              │
│                                                                    │
│  ┌─────────────────────────────────────┐                          │
│  │  Telegram Bot (separate process)    │                          │
│  │  aiogram + httpx → V1 API          │                          │
│  └─────────────────────────────────────┘                          │
│                                                                    │
│  Hosting: Railway (us-west2)                                      │
│  Domain: vaultvision.tech                                         │
└──────────────────────────────────────────────────────────────────┘
```

---

## Файловая структура

```
vaultvision/
├── back.py                  # Монолитный бэкенд (8500 строк)
├── vault-vision-v3.html     # Монолитный фронтенд (4000 строк)
├── vaultvision.db           # SQLite database
├── requirements.txt         # requests, Pillow
├── Procfile                 # web: python back.py
├── runtime.txt              # python-3.11.7
├── nixpacks.toml            # Railway build config
│
├── BUSINESS_LOGIC.md        # Бизнес-логика и стратегия
├── PRODUCT_ROADMAP.md       # Роадмап продукта
├── PROJECT_ARCHITECTURE.md  # Этот документ
├── RISK_ENGINE_V2_IMPLEMENTATION.md  # Документация risk engine
├── RAILWAY_DOMAIN_SETUP.md  # Гайд деплоя
│
├── vv bot/                  # Telegram бот (отдельный процесс)
│   ├── bot.py               # Aiogram бот (962 строк)
│   ├── db.py                # Bot SQLite layer (500 строк)
│   └── vaultvision_api.py   # API клиент (96 строк)
│
├── paper-trading.html       # Paper trading UI (legacy)
├── paper_trade.py           # Paper trading logic (legacy)
├── backtest_*.py            # Backtesting scripts (legacy)
└── fetch_btc.py             # BTC price fetcher (legacy)
```

---

## Бэкенд (back.py)

### Структура модулей (внутри одного файла)

```
back.py (8500 LOC)
│
├── CONFIG & CONSTANTS (строки 1-50)
│   ├── PORT = 8787
│   ├── FETCH_INTERVAL_SEC = 900 (15 мин)
│   └── BANNED_VAULTS = [...]
│
├── DATABASE LAYER (строки 50-400)
│   ├── init_db()              # Создание 12 таблиц
│   ├── get_db()               # Connection с WAL mode
│   ├── upsert_vault()         # Insert/update vault
│   ├── add_snapshot()         # Daily deduplicated snapshot
│   └── get_all_vaults()       # SELECT * WHERE protocol='hyperliquid'
│
├── DATA FETCHERS (строки 400-4500)
│   ├── fetch_hyperliquid()    # ОСНОВНОЙ: stats-data + clearinghouse
│   │   ├── Discovery: stats-data.hyperliquid.xyz/Mainnet/vaults
│   │   ├── Filter: top by TVL (>$500K)
│   │   ├── Enrich: api.hyperliquid.xyz/info (vaultDetails)
│   │   └── Parse: positions, leverage, exposure
│   ├── fetch_drift()          # DEPRECATED (код остался)
│   ├── fetch_lighter()        # DEPRECATED
│   └── fetch_nado()           # DEPRECATED
│
├── NORMALIZATION (строки 4500-4800)
│   ├── normalize_vault()      # Raw → canonical format
│   ├── normalize_snapshot()   # Raw → snapshot format
│   └── deduplicate_vaults()   # Remove dupes by pk
│
├── ANALYTICS ENGINE (строки 4800-5400)
│   ├── compute_vault_analytics()       # Main entry: 30d/90d metrics
│   ├── compute_daily_returns()         # Daily return %
│   ├── compute_cumulative_return()     # Product of (1+r_i)
│   ├── compute_volatility()            # Std dev of returns
│   ├── compute_max_drawdown()          # Peak-to-trough %
│   ├── compute_tvl_volatility()        # Std dev of log(TVL changes)
│   └── compute_apr_variance()          # Variance of APR
│
├── RISK ENGINE V2 (строки 5400-5900)
│   ├── run_risk_engine()               # Iterate all vaults
│   ├── compute_total_risk_score()      # Weighted sum
│   ├── compute_performance_risk()      # 35% weight
│   ├── compute_drawdown_risk()         # 25% weight
│   ├── compute_liquidity_risk()        # 25% weight
│   └── compute_confidence_risk()       # 15% weight
│
├── RANKING ENGINE (строки 5900-6100)
│   ├── run_rank_engine()               # 3 ranking types
│   ├── check_gating_verified_top()     # Eligibility
│   ├── check_gating_estimated_top()
│   └── check_gating_risk_adjusted()
│
├── ENTRY INTELLIGENCE (строки 6100-6250)
│   ├── run_hl_entry_intelligence()     # HL-specific
│   ├── fetch_hl_clearinghouse_state()  # Positions
│   ├── parse_hl_positions()            # Exposure, leverage
│   ├── compute_hl_flow_proxy()         # Net flows 24h/7d
│   └── compute_entry_score()           # 0-100 score
│
├── SIGNAL GENERATOR (строки 6250-6400)
│   └── v1_compute_signals()            # 7 signal types
│
├── EXPECTATION ENGINE (строки 6400-6500)
│   └── run_expectation_engine()        # Expected vs observed
│
├── FETCH JOB ORCHESTRATOR (строки 6500-6700)
│   └── run_fetch_job()                 # Full pipeline cycle:
│       │                                  fetch → normalize → validate
│       │                                  → store → analytics → risk
│       │                                  → rank → entry intel → signals
│       └── cleanup_old_vault_formats()
│
├── OG IMAGE GENERATOR (строки 7000-7200)
│   └── generate_og_image()             # Pillow-based PNG
│
├── API HANDLERS (строки 7200-8400)
│   │
│   ├── V1 API (stable, rate-limited, 60 req/min)
│   │   ├── GET /api/v1/health
│   │   ├── GET /api/v1/vaults [?protocol=&limit=]
│   │   ├── GET /api/v1/vaults/<id>
│   │   ├── GET /api/v1/rankings/verified [?limit=]
│   │   ├── GET /api/v1/rankings/estimated [?limit=]
│   │   ├── GET /api/v1/rankings/risk-adjusted [?limit=]
│   │   └── GET /api/v1/signals [?since_ts=&limit=]
│   │
│   ├── Internal API (fast, no rate limit)
│   │   ├── GET /api/vaults           # Full vault list
│   │   ├── GET /api/vault/<id>       # Vault detail
│   │   ├── GET /api/vault/<id>/history?days=90
│   │   ├── GET /api/vault/<id>/entry # Entry intel
│   │   ├── GET /api/rankings/<type>
│   │   ├── POST /api/track/click     # Revenue tracking
│   │   └── GET /api/click-stats
│   │
│   ├── Debug endpoints
│   │   ├── GET /api/debug/hl_entry
│   │   ├── GET /api/risk-sanity
│   │   ├── GET /api/analytics-debug
│   │   └── GET /api/system-status
│   │
│   └── Static
│       ├── GET /                      # vault-vision-v3.html
│       ├── GET /og-image.png          # Dynamic OG image
│       └── GET /paper-trading         # Legacy
│
└── MAIN (строки 8400-8540)
    ├── main()                          # Start server + bg thread
    ├── run_fetch_loop()                # Background fetch every 15m
    └── _has_recent_vault_data()        # Cold start check
```

---

## Database Schema

### Core таблицы

```sql
-- Canonical vault metadata
vaults (
    pk TEXT PRIMARY KEY,           -- "hyperliquid:0xabc..."
    protocol TEXT,                 -- "hyperliquid"
    vault_id TEXT,                 -- "0xabc..."
    vault_name TEXT,
    vault_type TEXT,               -- "user" | "protocol" | "strategy"
    deposit_asset TEXT DEFAULT 'USDC',
    leader TEXT,
    tvl_usd REAL,
    apr REAL,
    status TEXT DEFAULT 'active',  -- "active" | "hidden" | "banned"
    verified INTEGER DEFAULT 0,
    source_kind TEXT,              -- "real" | "derived" | "simulated"
    data_quality TEXT,             -- "mock" | "partial" | "full"
    first_seen_ts REAL,           -- sticky, never overwritten
    created_ts REAL
)

-- Time-series daily data
snapshots (
    vault_pk TEXT,
    ts REAL,                       -- Unix timestamp (daily bucket)
    tvl_usd REAL,
    apr REAL,                      -- Decimal: 0.15 = 15%
    return_7d REAL, return_30d REAL, return_90d REAL,
    pnl_7d REAL, pnl_30d REAL, pnl_90d REAL,
    confidence REAL,               -- 0.0-1.0
    quality_label TEXT,
    source TEXT,                   -- "api" | "derived" | "simulated"
    UNIQUE(vault_pk, ts)
)

-- Computed daily metrics
vault_analytics_daily (
    vault_pk TEXT,
    date_ts REAL,                  -- Day bucket
    daily_return REAL,
    cum_return_30d REAL, cum_return_90d REAL,
    volatility_30d REAL,
    worst_day_30d REAL,
    max_drawdown_30d REAL,
    tvl_volatility_30d REAL,
    apr_variance_30d REAL,
    data_points_30d INTEGER, data_points_90d INTEGER,
    UNIQUE(vault_pk, date_ts)
)

-- Risk scores
vault_risk_daily (
    vault_pk TEXT,
    protocol TEXT,
    date_ts REAL,
    risk_score REAL,               -- 0-100
    risk_band TEXT,                 -- "low" | "moderate" | "high"
    component_perf REAL,           -- 0-100
    component_drawdown REAL,
    component_liquidity REAL,
    component_confidence REAL,
    reasons_json TEXT,             -- JSON breakdown
    PRIMARY KEY(vault_pk, date_ts)
)

-- Rankings
vault_rank_daily (
    vault_pk TEXT,
    protocol TEXT,
    date_ts REAL,
    rank_type TEXT,                -- "verified_top" | "estimated_top" | "risk_adjusted"
    score REAL,
    rank INTEGER,                  -- 1..N
    included INTEGER,
    exclude_reason TEXT,
    PRIMARY KEY(vault_pk, date_ts, rank_type)
)

-- HL Entry Intelligence
hl_vault_state (
    ts REAL,
    vault_id TEXT,
    equity_usd REAL,
    gross_exposure_usd REAL,
    net_exposure_usd REAL,
    upnl_usd REAL, upnl_pct REAL,
    concentration_top1 REAL, concentration_top3 REAL,
    leverage_effective REAL,
    liq_risk TEXT,
    net_flow_24h REAL, net_flow_7d REAL,
    whale_outflow_7d REAL,
    entry_score REAL,              -- 0-100
    entry_label TEXT,              -- "GOOD_ENTRY" | "NEUTRAL" | "BAD_ENTRY"
    reasons TEXT
)

-- Revenue tracking
vault_click_events (
    ts REAL,
    vault_id TEXT,
    protocol TEXT,
    source_page TEXT,              -- "dashboard" | "vault_page" | "analytics"
    rank_type TEXT,
    user_agent TEXT,
    ip_hash TEXT,                  -- Privacy-safe
    ref_tag TEXT
)

-- Hourly PnL
pnl_history (
    vault_pk TEXT,
    ts REAL,
    pnl_usd REAL,
    account_value REAL,
    UNIQUE(vault_pk, ts)
)

-- System health
system_status (
    protocol TEXT PRIMARY KEY,
    last_success_fetch REAL,
    last_error TEXT,
    discovered_count INTEGER,
    active_count INTEGER,
    status TEXT                    -- "ok" | "stale" | "error"
)
```

---

## Data Pipeline

### Fetch Cycle (каждые 15 минут)

```
run_fetch_job()
│
├── 1. fetch_hyperliquid()
│   ├── GET stats-data.hyperliquid.xyz/Mainnet/vaults
│   │   → ~9000 raw vault entries
│   ├── Filter: TVL > $500K, not in BANNED_VAULTS
│   │   → ~23 vaults
│   ├── For each vault:
│   │   ├── POST api.hyperliquid.xyz/info {type: "vaultDetails"}
│   │   │   → APR, PnL, deposits, withdrawals
│   │   └── POST api.hyperliquid.xyz/info {type: "clearinghouseState"}
│   │       → positions, margins, leverage
│   └── Return normalized vault list
│
├── 2. normalize & validate
│   ├── normalize_vault() → canonical format
│   ├── Validate: APR>0, TVL>$500K
│   └── deduplicate_vaults()
│
├── 3. Store
│   ├── upsert_vault() for each vault
│   └── add_snapshot() for each vault (daily dedup)
│
├── 4. compute_all_vaults_analytics()
│   └── For each vault: returns, volatility, drawdown, etc.
│
├── 5. run_risk_engine()
│   └── For each vault: 5-component risk score
│
├── 6. run_rank_engine()
│   └── 3 ranking types: verified, estimated, risk-adjusted
│
├── 7. run_hl_entry_intelligence()
│   └── For each HL vault: entry score from positions/flows
│
└── 8. run_expectation_engine()
    └── Expected vs observed returns
```

### Timing

- Full cycle на Railway: ~7 минут
- Bottleneck: API calls к HL (rate limiting)
- Initial delay: 30 сек если есть свежие данные, 2 сек если нет

---

## Risk Engine V2

### Формула

```
risk_score = 0.35 × Perf + 0.25 × Drawdown + 0.25 × Liquidity + 0.15 × Confidence

Perf = 0.6 × vol_score(volatility_30d) + 0.4 × worst_day_score(worst_day_30d)
Drawdown = threshold_score(max_drawdown_30d)
Liquidity = 0.7 × tvl_size_score(tvl_usd) + 0.3 × tvl_vol_score(tvl_volatility)
Confidence = 0.7 × quality_score(quality_label) + 0.3 × history_score(data_points_30d)
```

### Risk Bands

| Score | Band | Color |
|-------|------|-------|
| 0-33 | Low | Green |
| 34-66 | Moderate | Yellow |
| 67-100 | High | Red |

---

## Ranking Engine

| Type | Formula | Gating |
|------|---------|--------|
| Verified Top | 0.55×APR + 0.30×TVL - 0.15×drawdown | quality=full, 30+ pts, TVL>$1M |
| Estimated Top | 0.70×APR + 0.30×TVL (×0.80 if simulated) | TVL>$500K, APR>0 |
| Risk-Adjusted | 0.40×return + 0.25×APR - 0.25×risk + 0.10×TVL | quality=full, 15+ pts, risk<85 |

---

## Frontend (vault-vision-v3.html)

### SPA Architecture

```
Single HTML file (4000 LOC)
│
├── <head> — Meta, OG tags, CSS (inline)
│
├── CSS (~700 lines)
│   ├── Variables (dark/light themes)
│   ├── Layout (responsive grid)
│   ├── Components (cards, badges, pills, tooltips)
│   ├── Pages (landing, dashboard, analytics, map, vault)
│   └── Animations (fade, slide, shimmer)
│
├── HTML (~400 lines)
│   ├── Landing Page (#pg-landing)
│   │   ├── Hero section
│   │   ├── Features grid
│   │   └── CTA buttons
│   ├── Dashboard (#pg-dashboard)
│   │   ├── Hero stats (TVL, APR, Count)
│   │   ├── Vault Map (mini, SVG)
│   │   ├── Protocol Vaults (HLP card)
│   │   ├── User Vaults grid
│   │   └── Best Risk-Adjusted table
│   ├── Analytics (#pg-analytics)
│   │   └── Sortable rankings table
│   ├── Compare (#pg-compare)
│   │   └── Multi-vault side-by-side
│   ├── Map (#pg-map)
│   │   ├── D3.js force graph (Explore mode)
│   │   └── Scatter plot (Risk/Return mode)
│   └── Vault Detail (#pg-vault)
│       ├── Key metrics cards
│       ├── Charts (TVL, APR, PnL, Returns)
│       ├── Risk breakdown (4 gauges)
│       ├── Entry Intelligence (HL)
│       └── Backtest calculator
│
├── JavaScript (~2900 lines)
│   ├── State Management (global vars)
│   ├── API calls (fetch /api/*)
│   ├── Rendering functions
│   ├── Chart rendering (Canvas API)
│   ├── D3.js map logic
│   ├── Theme toggle
│   ├── Navigation (SPA routing)
│   └── Utils (format, debounce, etc.)
│
└── D3.js (CDN, external)
```

### Pages

| Page | Route | Description |
|------|-------|-------------|
| Landing | `#landing` | Hero, features, CTA |
| Dashboard | `#dashboard` | Main view, stats, vault grid |
| Analytics | `#analytics` | Rankings table, sort/filter |
| Compare | `#compare` | Side-by-side vaults |
| Map | `#map` | D3 graph + scatter |
| Vault Detail | `#vault/ID` | Deep dive into one vault |

---

## Telegram Bot

### Architecture

```
vv bot/
├── bot.py (962 LOC, aiogram 3.x)
│   ├── Commands: /start, /vaults, /watchlist, /rankings, /alerts, /set_rules
│   ├── Inline buttons: add/remove vault from watchlist
│   ├── Alert polling loop: every 60s check V1 API signals
│   └── Anti-spam: max 20 alerts/day, 6h cooldown
│
├── db.py (500 LOC)
│   ├── users table (settings, language, cooldown)
│   ├── watchlist table (user→vault mapping)
│   ├── vault_apr_cache (latest APR/TVL per vault)
│   └── sent_alerts (dedup tracking)
│
└── vaultvision_api.py (96 LOC)
    ├── get_health()
    ├── get_vaults()
    ├── get_vault_by_id()
    ├── get_risk_adjusted_rankings()
    └── get_signals()
```

### Bot talks to back.py via V1 API (HTTP)

---

## Deployment

### Railway Config

```toml
# nixpacks.toml
[phases.setup]
aptPkgs = ["...", "libfreetype6-dev", "libjpeg-dev"]

[start]
cmd = "python back.py"
```

```
# Procfile
web: python back.py
```

```
# runtime.txt
python-3.11.7
```

### Environment

- Region: us-west2
- Persistent storage: SQLite DB file
- No external services (no Redis, no Postgres)
- Port: 8787 (Railway auto-routes to HTTPS)

### Deploy flow

```
git push → Railway auto-deploy → nixpacks build → python back.py
    → HTTP server starts on :8787
    → Background thread starts fetch loop
    → First fetch cycle: ~7 min
    → API serves cached DB data immediately
```

---

## Ключевые принципы архитектуры

1. **Monolith-first** — один файл бэкенд, один файл фронтенд. Быстро деплоим, легко дебажим
2. **SQLite + WAL** — zero-config database, достаточно для <10K concurrent users
3. **Background thread** — data fetch в отдельном потоке, не блокирует API
4. **15-min cycle** — баланс между свежестью данных и нагрузкой на HL API
5. **Graceful degradation** — если HL API упал, отдаем данные из DB (stale but valid)
6. **No auth yet** — все бесплатно, auth будет в Phase 3

---

## Что нужно улучшить (Tech Debt)

| Проблема | Приоритет | Решение |
|----------|-----------|---------|
| 8500 LOC в одном файле | Средний | Разбить на модули (fetchers/, engines/, api/) |
| 4000 LOC HTML | Средний | Build system (Vite/esbuild) или хотя бы минификация |
| No tests | Высокий | Unit tests для risk engine и analytics |
| No monitoring | Высокий | Sentry или простой error logging + alerts |
| SQLite locks under load | Низкий (пока) | PostgreSQL при >1K concurrent |
| No CI/CD | Средний | GitHub Actions: lint + test + deploy |
| OG image broken | Высокий | Fix Pillow install или static fallback |
| No backups | Высокий | Automated SQLite backup (daily) |

---

*Документ обновляется при архитектурных изменениях.*
