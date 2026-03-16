# VaultVision — Product Roadmap (HL-First)

> Post-pivot roadmap. Hyperliquid-only. Builder Codes monetization.
> Обновлено: март 2026

---

## Текущее состояние продукта

### Что работает (LIVE):
- Dashboard с ~23 vault'ами (top по TVL)
- Risk Engine v2 (5-компонентный score 0-100)
- 3 типа рейтингов (verified, estimated, risk-adjusted)
- Entry Intelligence (leverage, exposure, flows)
- 7 типов сигналов
- Vault Map (D3.js force graph + scatter plot)
- Compare (side-by-side)
- Vault Detail Page (charts, risk breakdown, backtest calculator)
- Telegram Bot (watchlist, alerts, rankings)
- V1 API (rate-limited, 7 endpoints)
- Click tracking

### Что НЕ работает / не сделано:
- Builder Code не зарегистрирован
- OG image generation (501 на production)
- User auth / accounts
- Premium tier / Stripe
- Portfolio tracking
- Mobile optimization (частичная)
- Twitter content automation

---

## Phase 1: Builder Code + Polish (Неделя 1-2)

**Цель:** Запустить монетизацию через Builder Code. Убрать все баги.

### 1.1 Builder Code Integration
- [ ] Зарегистрировать Builder Code на HL (100 USDC)
- [ ] Добавить `?builder=VAULTVISION` к deposit ссылкам
- [ ] Реализовать `ApproveBuilderFee` flow
- [ ] Dashboard для отслеживания referral revenue
- [ ] Обновить "Deposit via VaultVision" кнопку

### 1.2 Bug Fixes & Polish
- [ ] Починить OG image (Pillow на Railway или fallback static image)
- [ ] Landing page: убрать "BUILT FOR" пустую секцию
- [ ] "Powered by" — показывать корректное кол-во vault'ов
- [ ] Dark mode по умолчанию для новых пользователей
- [ ] Speed: минифицировать HTML (240KB → ~100KB)
- [ ] Speed: lazy load charts и map
- [ ] Mobile: проверить все страницы на 375px

### 1.3 Content для launch
- [ ] Подготовить Twitter thread "VaultVision is LIVE"
- [ ] Подготовить 5 vault card images для Twitter
- [ ] Landing page call-to-action: "Track every HL vault"

---

## Phase 2: Telegram Bot Pro + Whale Tracking (Неделя 3-4)

**Цель:** Монетизировать бота. Добавить whale tracking как killer feature.

### 2.1 Whale Tracking (Free)
- [ ] Отслеживать крупные deposit/withdraw (>$50K) в HL vault'ы
- [ ] Показывать whale flows на vault detail page
- [ ] "Whale Activity" секция на dashboard
- [ ] Signal: WHALE_DEPOSIT, WHALE_WITHDRAW

### 2.2 Telegram Bot Pro ($9/мес)
- [ ] Stripe интеграция в боте (или crypto payment)
- [ ] Pro features:
  - Unlimited watchlist (free: 3 vault'а)
  - Real-time whale alerts (free: daily digest only)
  - Custom alert rules (APR > X%, Risk < Y)
  - Priority signal delivery
  - Portfolio tracking в боте
- [ ] Payment flow: /upgrade → Stripe checkout → Pro badge

### 2.3 Bot Improvements
- [ ] /deposit command — прямая ссылка с Builder Code
- [ ] /compare vault1 vault2 — сравнение в боте
- [ ] /risk vault_name — risk breakdown
- [ ] Inline mode — @VaultVisionBot HLP → показывает карточку vault'а

---

## Phase 3: Web Pro + Advanced Analytics (Неделя 5-8)

**Цель:** Premium web tier. Retention через глубокую аналитику.

### 3.1 User Accounts
- [ ] Simple auth (email + magic link, без паролей)
- [ ] Saved watchlist (DB вместо localStorage)
- [ ] User preferences (default sort, favorite vaults)

### 3.2 Pro Tier ($29/мес)
- [ ] Stripe subscription
- [ ] Feature gating
- [ ] Pro features:
  - Advanced Metrics: Sharpe, Sortino, Calmar Ratio
  - Benchmarking: vault APR vs BTC, ETH, USDC lending
  - Export: CSV, PDF reports
  - Portfolio Tracking: track your deposits across vault'ов
  - Custom Dashboard: pin vaults, reorder
  - Risk Scenarios: "what if TVL drops 50%"

### 3.3 Advanced Charts
- [ ] Vault detail: rolling Sharpe Ratio (30d)
- [ ] Drawdown chart (визуализация просадок)
- [ ] Flow chart (deposit/withdraw timeline)
- [ ] Correlation matrix (между top vault'ами)

### 3.4 Backtest Engine V2
- [ ] Improve accuracy (use real PnL data, not simulated)
- [ ] Multi-vault portfolio backtest
- [ ] Comparison: "if you deposited $10K in HLP vs Vault X 90 days ago"

---

## Phase 4: Growth + Ecosystem (Месяц 3-6)

**Цель:** Масштабирование. HL ecosystem integration.

### 4.1 Twitter Automation
- [ ] Auto-post daily: "Top 5 HL vaults today"
- [ ] Auto-post weekly: "HL Vault Weekly Digest"
- [ ] Signal alerts: tweet when major APR_SPIKE/OUTFLOW
- [ ] Vault card images (auto-generated OG cards)

### 4.2 SEO
- [ ] Unique URL для каждого vault'а: vaultvision.tech/vault/HLP
- [ ] Meta tags per vault page (dynamic OG)
- [ ] Blog section: "How to choose an HL vault" guides

### 4.3 HL Ecosystem Integration
- [ ] Apply for HL ecosystem page listing
- [ ] Partnership с крупными vault leaders
- [ ] Embed widget для vault leaders ("Powered by VaultVision")
- [ ] HL Discord presence

### 4.4 API Monetization
- [ ] API keys + rate limiting per key
- [ ] Developer portal (docs, examples)
- [ ] Webhook subscriptions (push alerts)
- [ ] Developer tier ($49/мес)

### 4.5 More Vault Coverage
- [ ] Увеличить с 23 до 100+ vault'ов (снизить TVL filter)
- [ ] Categorization: market-making, basis trading, momentum, etc.
- [ ] Vault leader profiles

---

## Phase 5: Scale (Месяц 6+)

### 5.1 Technical
- [ ] Migrate SQLite → PostgreSQL (при >1K concurrent users)
- [ ] CDN для static assets (Cloudflare)
- [ ] Separate frontend build (React/Next.js vs monolith HTML)
- [ ] Real-time WebSocket updates

### 5.2 Product
- [ ] Mobile app (React Native / PWA)
- [ ] Social features: public portfolios, leaderboard
- [ ] Multi-protocol return (добавить другие протоколы если нужно)
- [ ] AI-powered vault recommendations

### 5.3 Revenue
- [ ] Data licensing (historical risk scores for researchers)
- [ ] White-label for vault leaders
- [ ] Enterprise API tier

---

## Метрики успеха по фазам

| Phase | Срок | Ключевая метрика | Target |
|-------|------|-----------------|--------|
| 1 | Неделя 1-2 | Builder Code revenue | >$0 (первый доход) |
| 2 | Неделя 3-4 | Telegram Bot Pro subs | 10 платящих |
| 3 | Неделя 5-8 | Web Pro subs | 20 платящих |
| 4 | Месяц 3-6 | MAU | 3,000 |
| 5 | Месяц 6+ | MRR | $5,000 |

---

## Quick Wins (можно сделать за 1 день)

1. **Builder Code registration** — 100 USDC, мгновенная монетизация
2. **Dark mode default** — 1 строка кода, лучше UX для крипто
3. **OG image fix** — static fallback если Pillow не работает
4. **Twitter card** — красивый preview при шаринге ссылки
5. **Vault count fix** — показывать реальное число, не 6
6. **"BUILT FOR" fix** — убрать пустую секцию

---

*Roadmap обновляется еженедельно. Приоритеты могут меняться на основе user feedback и метрик.*
