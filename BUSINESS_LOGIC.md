# VaultVision — Бизнес-логика (HL-First Pivot)

> Стратегический документ после пивота на Hyperliquid-only.
> Последнее обновление: март 2026

---

## 1. Executive Summary

**VaultVision** — аналитическая платформа для vault'ов Hyperliquid.
Risk scores, whale tracking, entry intelligence, сигналы.

**Миссия:** дать инвестору ответ "куда вложить на HL и когда" за 60 секунд.

**Стадия:** LIVE. Продукт работает, данные обновляются каждые 15 минут.

**Пивот:** отказ от мульти-протокольного агрегатора (Drift, Lighter, Nado убраны).
Причина — 95%+ TVL и пользователей на Hyperliquid. Глубина > ширина.

### Ключевые метрики (факт)

| Метрика | Значение |
|---------|----------|
| Протокол | Hyperliquid (только) |
| Активных vault'ов | ~23 (фильтр по TVL) |
| HL vaults на рынке | 9000+ (мы показываем top) |
| Общий TVL покрытие | ~$350M+ |
| Risk scoring | 100% vault'ов |
| Типов рейтингов | 3 (verified, estimated, risk-adjusted) |
| Типов сигналов | 7 |
| Entry Intelligence | Да (leverage, flows, positions) |
| Цикл обновления | 15 минут |

---

## 2. Почему Hyperliquid-only

### 2.1 Рыночные аргументы

| Фактор | HL | Drift | Lighter | Nado |
|--------|-----|-------|---------|------|
| Vault TVL | $350M+ | $24M | $228M (но locked) | $2M |
| Активные vault'ы | 9000+ | 18 | 5 | 1 |
| Depositor activity | Очень высокая | Средняя | Низкая | Минимальная |
| Builder Codes (revshare) | Да | Нет | Нет | Нет |
| API quality | Отличное | Хорошее | Среднее | Нет |

### 2.2 Стратегическое обоснование

1. **Builder Codes** — единственный протокол с нативным revshare механизмом
2. **Глубина данных** — clearinghouse API дает leverage, positions, flows
3. **Community** — самое большое и активное крипто-сообщество 2025-26
4. **Vault ecosystem** — 9000+ vault'ов, реальная конкуренция между ними
5. **Moat** — стать "the analytics tool" для HL vault depositors

### 2.3 Что теряем

- Нарратив "единственный кросс-протокольный агрегатор"
- Потенциальных пользователей Drift/Lighter (но их мало)
- Diversification по протоколам

### 2.4 Что приобретаем

- Фокус — один протокол = глубже аналитика, лучше UX
- Builder Codes — прямая монетизация с Day 1
- Нишевый авторитет — "VaultVision = HL vault analytics"
- Скорость — не нужно поддерживать 4 API, 4 нормализации

---

## 3. Монетизация

### 3.1 Основная модель: Builder Codes (Fee Share)

**Механика:**
1. Регистрируем Builder Code на Hyperliquid (100 USDC one-time)
2. Интегрируем `ApproveBuilderFee` в deposit flow
3. Когда пользователь VaultVision делает депозит через нашу ссылку — HL берет небольшую комиссию
4. Часть комиссии идет VaultVision как builder

**Flow:**
```
User на VaultVision → "Deposit via VaultVision" →
→ app.hyperliquid.xyz/vaults/{id}?builder=VAULTVISION →
→ User делает deposit → HL берет fee →
→ VaultVision получает builder share
```

**Оценка дохода:**
- Если 50 депозитов/день, средний $5K
- $250K/день volume × builder fee 0.01-0.1%
- **$25-250/день = $750-7,500/мес**

### 3.2 Вторичная модель: Data Premium

| | Free | Pro ($29/мес) |
|--|------|---------------|
| Все vault'ы и метрики | Да | Да |
| Risk scores & rankings | Да | Да |
| Vault Map | Да | Да |
| Entry Intelligence (базовый) | Да | Да |
| Advanced Metrics (Sharpe, Sortino, Calmar) | — | Да |
| Export CSV / PDF отчеты | — | Да |
| Custom Alerts (Telegram/Email) | — | Да |
| Portfolio Tracking | — | Да |
| Whale flow alerts | — | Да |
| API access (10K req/day) | — | Да |

### 3.3 API Access

| Тариф | Цена | Лимиты |
|-------|------|--------|
| Free | $0 | 100 req/day, базовые endpoints |
| Developer | $49/мес | 50K req/day, все endpoints |
| Enterprise | Custom | Unlimited, webhooks, SLA |

### 3.4 Приоритизация Revenue Streams

```
1. Builder Codes       ████████████████  Приоритет #1 (сейчас)
   → Нет зависимости от кол-ва пользователей
   → Прямая монетизация трафика
   → Единственная затрата: 100 USDC на регистрацию

2. Telegram Bot Pro    ████████████      Приоритет #2 (1-2 мес)
   → Whale alerts, watchlist, сигналы
   → $9/мес подписка в боте
   → Низкий CAC через HL community

3. Web Pro Tier        ████████          Приоритет #3 (2-3 мес)
   → Auth + Stripe + feature gating
   → $29/мес
   → Нужна user base

4. API                 ██████            Приоритет #4 (3+ мес)
   → V1 API уже работает
   → Нужны разработчики-потребители
```

---

## 4. Ценностное предложение

### 4.1 Value Chain

```
HL API (9000+ vaults)
    ↓
VaultVision Pipeline (каждые 15 мин)
    ├── Discovery — находим top vault'ы по TVL
    ├── Enrichment — positions, leverage, flows
    ├── Analytics — returns, volatility, drawdown
    ├── Risk Engine — 5-компонентный score 0-100
    ├── Rankings — 3 типа (verified, estimated, risk-adjusted)
    ├── Entry Intelligence — когда входить
    └── Signals — 7 типов (APR_SPIKE, OUTFLOW, etc.)
    ↓
Продукты
    ├── Web Dashboard — browse, analyze, compare, map
    ├── Telegram Bot — alerts, watchlist, rankings
    └── V1 API — для ботов и интеграций
    ↓
Ценность
    ├── Обнаружение — "какие vault'ы есть на HL?"
    ├── Оценка — "насколько безопасен этот vault?"
    ├── Тайминг — "входить сейчас или ждать?"
    └── Мониторинг — "предупреди если что-то не так"
```

### 4.2 Уникальные data assets

| Data Asset | Почему ценно |
|------------|-------------|
| Risk scores для каждого HL vault | HL сам не дает risk scoring |
| Entry Intelligence (leverage, exposure, flows) | Никто не агрегирует clearinghouse data в понятный score |
| Cross-vault rankings (risk-adjusted) | HL показывает vault'ы по TVL/PnL, мы — по risk/return |
| Temporal signals (APR_SPIKE, OUTFLOW) | Раннее обнаружение проблем — раньше, чем заметит человек |
| Накопленная история | Daily snapshots растут со временем → backtesting |

---

## 5. Сегменты пользователей

### 5.1 Primary: HL Vault Depositor (80%)

**Профиль:** крипто-нативный инвестор с $1K-100K, ищет пассивный доход на HL
**Боль:** 9000 vault'ов, непонятно куда вложить, нет risk метрик
**Job-to-be-Done:** "Хочу найти безопасный vault с хорошей доходностью"
**Как VaultVision решает:** Rankings + Risk Score + Entry Intelligence

### 5.2 Secondary: HL Whale (15%)

**Профиль:** $100K+ капитал, нужен deep due diligence
**Боль:** нет инструмента для анализа позиций vault leader'а
**Job-to-be-Done:** "Хочу видеть leverage, exposure, flows прежде чем вкладывать $500K"
**Как VaultVision решает:** Entry Intel + Whale flow tracking + History

### 5.3 Tertiary: Vault Leader (5%)

**Профиль:** создатель vault'а на HL, хочет привлечь depositors
**Боль:** нет маркетинговой площадки, HL показывает все 9000 vault'ов одинаково
**Job-to-be-Done:** "Хочу чтобы мой vault был заметен"
**Как VaultVision решает:** Rankings (если vault хороший — он в топе)

---

## 6. Конкурентный ландшафт

| Инструмент | Что делает | Чего нет |
|-----------|-----------|---------|
| **app.hyperliquid.xyz/vaults** | Нативный список vault'ов HL | Нет risk scores, нет Entry Intel, нет сигналов, нет сравнения |
| **DeFiLlama** | TVL каталог всех DeFi | Нет HL vault специфики, нет risk model |
| **stats.hyperliquid.xyz** | Базовая статистика HL | Нет vault analytics |
| **VaultVision** | Risk scores + Rankings + Entry Intel + Signals + Map + Compare | — |

**Прямых конкурентов в нише HL vault analytics нет.**

Ближайший "конкурент" — нативная страница HL, но она показывает raw данные без risk scoring и intelligence layer.

---

## 7. Growth Strategy

### 7.1 Flywheel

```
Лучше аналитика HL vault'ов
    → Больше depositors используют VaultVision
    → Больше deposits через Builder Code
    → Больше revenue
    → Инвестиции в продукт
    → Ещё лучше аналитика
```

### 7.2 Каналы привлечения

**Twitter/X (приоритет #1):**
- Ежедневные посты: "Top 5 HL vaults by risk-adjusted return"
- Еженедельные: "HL Vault Weekly Digest"
- Signal alerts: "APR SPIKE на vault X — что происходит?"
- Target: HL community (200K+ followers в экосистеме)

**Hyperliquid ecosystem:**
- Попасть в HL ecosystem page
- Partnerships с крупными vault leaders
- Presence в HL Discord/Telegram

**Telegram Bot:**
- Органический рост через HL группы
- Пользователь пробует бота → переходит на сайт
- Форвард алертов в группы

**SEO:**
- "hyperliquid vault risk", "best HL vault", "hyperliquid vault analytics"
- Каждый vault detail page = уникальная SEO-страница

### 7.3 Milestones

| Период | Цель | Метрика |
|--------|------|---------|
| Неделя 1-2 | Builder Code зарегистрирован, deposit flow работает | Первый revshare |
| Месяц 1 | Twitter strategy запущена, 500 impressions/tweet | 100 MAU |
| Месяц 2 | Telegram Bot с pro-features, whale alerts | 500 MAU, 50 bot users |
| Месяц 3 | Web Pro tier, Stripe | 1K MAU, 20 платящих |
| Месяц 6 | API customers, data licensing | 3K MAU, $5K MRR |

---

## 8. Unit Economics

### 8.1 Расходы

| Статья | Сейчас | При 3K MAU |
|--------|--------|------------|
| Railway hosting | $5-20/мес | $50/мес |
| Домен | $12/год | $12/год |
| Builder Code registration | 100 USDC (one-time) | — |
| Telegram Bot API | $0 | $0 |
| Stripe (2.9% + $0.30) | $0 | ~$50/мес |
| **Итого** | **~$20/мес** | **~$100/мес** |

### 8.2 Revenue проекции

| Метрика | 1 мес | 3 мес | 6 мес |
|---------|-------|-------|-------|
| MAU | 100 | 500 | 3,000 |
| Builder Code revenue | $100 | $500 | $2,000 |
| Bot Pro subscribers | 0 | 20 | 100 |
| Web Pro subscribers | 0 | 5 | 30 |
| **MRR** | **$100** | **$800** | **$3,870** |
| Расходы | $25 | $50 | $100 |
| **Прибыль** | **$75** | **$750** | **$3,770** |

### 8.3 Breakeven

При расходах ~$20/мес breakeven достигается с **2-3 успешных deposit referrals в месяц** через Builder Code. Порог входа: 100 USDC.

---

## 9. Риски и митигация

| Риск | Вероятность | Импакт | Митигация |
|------|-------------|--------|-----------|
| HL изменит vault API | Средняя | Высокий | Быстрый hotfix, fallback к DB |
| HL уберет Builder Codes | Низкая | Критический | Диверсификация: Pro subscriptions, API |
| Конкурент (HL-native analytics) | Средняя | Высокий | Speed, data moat, community trust |
| Bear market | Средняя | Средний | Vault'ы нужны и в bear'е (hedging), risk intel важнее |
| Зависимость от одного протокола | Высокая | Средний | Если HL растет — мы растем. При необходимости добавим другие протоколы |

---

## 10. North Star Metric

**"Deposits through VaultVision per month"**

Количество deposit'ов в HL vault'ы, которые прошли через VaultVision (Builder Code tracking).

Это единственная метрика, которая напрямую = revenue.

**Proxy metrics:**
- Vault detail page views → leading indicator
- "Deposit via VaultVision" clicks → conversion funnel
- Return visits → retention
- Bot alert open rate → engagement

---

*Документ обновляется при существенных изменениях в продукте или бизнес-модели.*
