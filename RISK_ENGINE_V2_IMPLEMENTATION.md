# Risk Engine v2 + Rankings (Phase 2.5) — Реализация

## Обзор

Risk Engine v2 — детерминированная, объяснимая система оценки рисков для DeFi vaults.

**Ключевые характеристики:**
- 4 компонента риска с прозрачными весами
- Детерминированные пороги (без ML/случайности)
- Полное объяснение каждого score через tooltips
- Fallback-логика для работы с минимальными данными

---

## Архитектура

```
run_fetch_job()
    │
    ├── Step 1-3: Fetch → Normalize → Store
    │
    ├── Step 4: compute_all_vaults_analytics()
    │   ├── compute_vault_analytics()             # Если ≥2 snapshots
    │   └── compute_basic_analytics_from_vault()  # Если 1 snapshot
    │
    └── Step 5: run_risk_engine()
        ├── Если есть analytics → использует analytics данные
        └── Если нет → compute_risk_components_from_vault_data()
        
        Результат: vault_risk_daily table

get_all_vaults()
    │
    ├── Читает из vault_risk_daily
    └── Возвращает risk_score, risk_band, risk_components, risk_reasons

Frontend renderRiskBreakdown()
    │
    ├── Использует risk_components из backend
    └── Показывает 4 компонента с tooltips
```

---

## База данных

### Таблица `vault_risk_daily`

```sql
CREATE TABLE vault_risk_daily (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_pk TEXT NOT NULL,
    protocol TEXT NOT NULL,
    date_ts INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,          -- 0-100, итоговый риск
    risk_band TEXT NOT NULL,              -- "low" | "moderate" | "high"
    component_perf INTEGER NOT NULL,      -- Performance Risk (0-100)
    component_drawdown INTEGER NOT NULL,  -- Drawdown Risk (0-100)
    component_liquidity INTEGER NOT NULL, -- Liquidity Risk (0-100)
    component_confidence INTEGER NOT NULL,-- Data Confidence Risk (0-100)
    reasons_json TEXT,                    -- JSON с деталями расчета
    computed_ts INTEGER NOT NULL,
    UNIQUE(vault_pk, date_ts)
)
```

---

## Компоненты риска

### 1. Performance Risk (вес: 35%)

**Входные данные:**
- `volatility_30d` — стандартное отклонение дневных returns за 30 дней
- `worst_day_30d` — минимальный дневной return за 30 дней

**Volatility mapping:**
| Volatility | Score |
|------------|-------|
| ≤ 0.3%     | 10    |
| ≤ 1%       | 25    |
| ≤ 2%       | 45    |
| ≤ 4%       | 65    |
| > 4%       | 85    |

**Worst day mapping:**
| Worst Day | Score |
|-----------|-------|
| ≤ 0.5%    | 10    |
| ≤ 2%      | 35    |
| ≤ 5%      | 65    |
| > 5%      | 90    |

**Формула:** `component_perf = 0.6 × vol_score + 0.4 × worst_day_score`

---

### 2. Drawdown Risk (вес: 25%)

**Входные данные:**
- `max_drawdown_30d` — максимальное падение peak-to-trough за 30 дней

**Mapping:**
| Max Drawdown | Score |
|--------------|-------|
| ≤ 1%         | 10    |
| ≤ 5%         | 35    |
| ≤ 12%        | 60    |
| ≤ 25%        | 80    |
| > 25%        | 95    |

---

### 3. Liquidity Risk (вес: 25%)

**Входные данные:**
- `tvl_usd` — Total Value Locked в USD
- `tvl_volatility_30d` — волатильность TVL

**TVL size mapping:**
| TVL          | Score |
|--------------|-------|
| ≥ $100M      | 10    |
| ≥ $20M       | 20    |
| ≥ $5M        | 35    |
| ≥ $1M        | 55    |
| < $1M        | 75    |

**TVL volatility mapping:**
| TVL Volatility | Score |
|----------------|-------|
| ≤ 1%           | 15    |
| ≤ 3%           | 35    |
| ≤ 8%           | 60    |
| > 8%           | 85    |

**Формула:** `component_liquidity = 0.7 × tvl_size_score + 0.3 × tvl_vol_score`

---

### 4. Data Confidence Risk (вес: 15%)

**Входные данные:**
- `quality_label` — "real" | "derived" | "simulated" | "demo"
- `data_points_30d` — количество точек данных за 30 дней

**Quality mapping:**
| Quality    | Score |
|------------|-------|
| real       | 10    |
| derived    | 25    |
| simulated  | 45    |
| demo       | 70    |

**History mapping:**
| Data Points | Score |
|-------------|-------|
| ≥ 30        | 10    |
| ≥ 20        | 20    |
| ≥ 10        | 35    |
| < 10        | 55    |

**Формула:** `component_confidence = 0.7 × quality_score + 0.3 × history_score`

---

## Итоговый Risk Score

**Формула:**
```
risk_score = 0.35 × perf + 0.25 × drawdown + 0.25 × liquidity + 0.15 × confidence
```

**Risk Bands:**
| Score Range | Band     |
|-------------|----------|
| 0–33        | Low      |
| 34–66       | Moderate |
| 67–100      | High     |

---

## API Response

```json
{
  "id": "hyperliquid:0x1234...",
  "vault_name": "Vault Name",
  "risk_score": 45,
  "risk_band": "moderate",
  "risk_components": {
    "perf": 35,
    "drawdown": 50,
    "liquidity": 25,
    "confidence": 40
  },
  "risk_reasons": {
    "volatility_30d": 0.015,
    "worst_day_30d": -0.02,
    "max_drawdown_30d": 0.05,
    "tvl_usd": 5000000,
    "tvl_volatility_30d": 0.02,
    "quality_label": "derived",
    "data_points_30d": 25,
    "notes": ["missing tvl_volatility_30d -> using mid-risk default"]
  }
}
```

---

## Fallback-логика

### Когда analytics недоступна

Если в `vault_analytics_daily` нет данных, система использует `compute_risk_components_from_vault_data()`:

1. **Performance Risk** — оценка из `pnl_30d` и `apr`:
   - `volatility_30d ≈ abs(pnl_30d) × 0.2`
   - `worst_day_30d ≈ pnl_30d × 0.4` (если отрицательный)

2. **Drawdown Risk** — оценка из `pnl_30d`/`pnl_90d`:
   - `max_drawdown_30d ≈ abs(pnl_30d) × 0.6` (если отрицательный)

3. **Liquidity Risk** — использует реальный `tvl_usd`

4. **Confidence Risk** — использует `data_quality` и `age_days`

### Когда только 1 snapshot

Функция `compute_basic_analytics_from_vault()` создает базовую analytics запись, используя данные из таблицы `vaults`.

---

## Frontend интеграция

### renderRiskBreakdown()

```javascript
function renderRiskBreakdown(vault, riskScore) {
  if (vault.risk_components && typeof vault.risk_components === 'object') {
    // Используем backend данные
    const rc = vault.risk_components;
    const getLabel = (score) => {
      if (score <= 33) return 'Low';
      if (score <= 66) return 'Moderate';
      return 'High';
    };
    // ... render components
  } else {
    // Fallback на клиентскую логику
  }
}
```

### Tooltips

Показывают реальные значения из `risk_reasons`:
- Performance: "Volatility: 1.50%, Worst day: -2.00%"
- Drawdown: "Max drawdown: 5.00%"
- Liquidity: "TVL: $5.00M, TVL volatility: 2.00%"
- Confidence: "Data quality: derived, History: 25 points"

---

## Коммиты

1. `d4b3e2e` — Frontend: использует Risk Engine v2 компоненты
2. `e0978c3` — Исправлены пороги меток (Low/Moderate/High)
3. `a9e0ccc` — Fallback вычисляет компоненты из vault данных
4. `d948a13` — Risk engine работает без analytics
5. `9596b45` — Analytics создается с 1 snapshot
6. `6801ecb` — SQL-запросы исправлены (pnl_30d/pnl_90d)

---

## Тестирование

После запуска `run_fetch_job()` в логах должно быть:
```
[ANALYTICS] Computing analytics for 34 vaults...
[ANALYTICS] Done. Computed 34 analytics rows in 0.1s
[FETCH] Analytics: 34 new rows computed in 0.1s
[FETCH] Step 5: Computing risk scores...
[RISK] Computing risk scores for 34 vaults (target_date=...)
[RISK] Done: 34 computed, 0 skipped, 0 errors in 0.01s
```

Frontend показывает:
- Risk gauge с итоговым score
- 4 компонента с разными значениями
- Tooltips с реальными метриками

---

# Phase 2.5: Rankings (Rank Engine v1)

## Обзор

Rank Engine добавляет три типа рейтингов с gating rules:
- **Verified Top** — только verified данные
- **Estimated Top** — включая simulated (с penalty)
- **Risk-Adjusted** — return per unit risk

## База данных

### Таблица `vault_rank_daily`

```sql
CREATE TABLE vault_rank_daily (
    vault_pk TEXT NOT NULL,
    protocol TEXT NOT NULL,
    date_ts INTEGER NOT NULL,
    rank_type TEXT NOT NULL,     -- "verified_top" | "estimated_top" | "risk_adjusted"
    score REAL NOT NULL,         -- Higher = better
    rank INTEGER NOT NULL,       -- 1..N (1 = best)
    included INTEGER NOT NULL,   -- 1 = included, 0 = excluded
    exclude_reason TEXT,
    computed_ts INTEGER NOT NULL,
    PRIMARY KEY (vault_pk, date_ts, rank_type)
)
```

---

## Gating Rules

### 1. Verified Top
| Rule | Requirement |
|------|-------------|
| quality_label | IN ("real", "derived") |
| data_points_30d | >= 10 |
| tvl_usd | >= $500K |
| apr | > 0 |

**Demo/simulated NEVER included.**

### 2. Estimated Top
| Rule | Requirement |
|------|-------------|
| quality_label | IN ("real", "derived", "simulated") — NO demo |
| tvl_usd | >= $500K |
| apr | > 0 |

### 3. Risk-Adjusted
| Rule | Requirement |
|------|-------------|
| quality_label | NOT "demo" |
| data_points_30d | >= 10 |
| tvl_usd | >= $1M (stricter) |
| risk_score | exists |
| return data | cum_return_30d OR apr |

---

## Scoring Formulas

### 1. Verified Top Score
```
score = 0.55 × norm(apr) + 0.30 × norm(tvl) - 0.15 × norm(drawdown)
```

**Normalization:**
- `norm(apr)`: APR 0..60% → 0..1
- `norm(tvl)`: log scale, $500K..$500M → 0..1
- `norm(drawdown)`: drawdown 0..25% → 0..1

### 2. Estimated Top Score
```
score = 0.70 × norm(apr) + 0.30 × norm(tvl)
```
**Penalty:** `score × 0.80` if quality_label == "simulated"

### 3. Risk-Adjusted Score
```
expected_return = cum_return_30d OR apr/12
risk_penalty = max(0.15, risk_score/100)
base_score = expected_return / risk_penalty
tvl_factor = 0.8 + 0.2 × norm(tvl)
score = base_score × tvl_factor
```

---

## API Endpoints

### GET /api/rankings/verified?limit=50
### GET /api/rankings/estimated?limit=50
### GET /api/rankings/risk-adjusted?limit=50

**Query params:**
- `limit` — 1..200, default 50
- `include_excluded=1` — show excluded vaults with reasons

**Response:**
```json
{
  "rank_type": "verified_top",
  "date_ts": 1706745600,
  "total_included": 15,
  "total_excluded": 19,
  "rankings": [
    {
      "vault_id": "hyperliquid:0x1234...",
      "protocol": "hyperliquid",
      "vault_name": "Alpha Vault",
      "tvl_usd": 5000000,
      "apr": 0.25,
      "risk_score": 35,
      "risk_band": "moderate",
      "rank": 1,
      "score": 0.7234,
      "included": true,
      "quality_label": "derived",
      "data_points_30d": 25
    }
  ]
}
```

---

## Integration

### run_fetch_job() Pipeline
```
Step 1-3: Fetch → Normalize → Store
Step 4: compute_all_vaults_analytics()
Step 5: run_risk_engine()
Step 6: run_rank_engine()  ← NEW
```

### get_all_vaults() Response
Each vault now includes:
```json
{
  "rankings": {
    "verified_top": {"rank": 3, "score": 0.65},
    "estimated_top": {"rank": 2, "score": 0.72},
    "risk_adjusted": {"rank": 5, "score": 0.45}
  }
}
```

---

## Debug Output

### /api/vaults?debug=1

New fields:
```json
{
  "rank_counts": {
    "verified_top": {"included": 12, "excluded": 22},
    "estimated_top": {"included": 20, "excluded": 14},
    "risk_adjusted": {"included": 8, "excluded": 26}
  },
  "rank_top10": {
    "verified_top": [
      {"rank": 1, "vault_name": "...", "score": 0.75, ...}
    ]
  },
  "rank_exclusion_reasons": {
    "verified_top": [
      {"reason": "quality_label=simulated (need real/derived)", "count": 10},
      {"reason": "data_points_30d=5 (need >=10)", "count": 8}
    ]
  },
  "acceptance_checks": {
    "demo_not_in_verified": true,
    "rankings_populated": true
  }
}
```

---

## Acceptance Checklist

- [x] Demo vaults NEVER in verified_top or risk_adjusted
- [x] Simulated vaults NEVER in verified_top
- [x] Rankings stable across server restarts
- [x] All endpoints respond <50ms (precomputed from DB)
- [x] Exclude reasons correct and useful
- [x] No duplicates (vault_pk unique per protocol)

---

## Коммиты Phase 2.5

1. `9040be1` — Implement Phase 2.5: Risk Gating and Rankings
