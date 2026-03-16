# VaultVision — Недельный план улучшений

> Неделя 16-22 марта 2026
> Фокус: Builder Code + Bug Fixes + Growth Foundations

---

## Понедельник (17 марта) — Builder Code & Core Fixes

### Утро: Builder Code Registration
- [ ] Зарегистрировать Builder Code на Hyperliquid (100 USDC)
- [ ] Получить builder address / code string
- [ ] Документировать процесс в README

### День: Deposit Flow Integration
- [ ] Обновить все vault ссылки: добавить `?builder=VAULTVISION` параметр
- [ ] Кнопка "Deposit via VaultVision" — проверить что открывает правильный URL
- [ ] Добавить click tracking: при клике на deposit → POST /api/track/click
- [ ] Проверить что builder fee проходит (тестовый депозит)

### Вечер: Critical Bug Fixes
- [ ] Fix OG image: static fallback PNG если Pillow не работает на Railway
- [ ] Fix "BUILT FOR" пустая секция на landing page — убрать или заполнить
- [ ] Fix "Powered by X vaults" — показывать реальный count
- [ ] Dark mode по умолчанию (initTheme fallback)

---

## Вторник (18 марта) — UI Polish & Performance

### Утро: Landing Page Redesign
- [ ] Проверить layout Vault Map + HLP на production
- [ ] Обновить hero текст: "Track every vault on Hyperliquid"
- [ ] Убрать все упоминания Drift/Lighter/Nado (полная ревизия)
- [ ] Badge: BETA → LIVE (зелёный)

### День: Performance Optimization
- [ ] Минификация vault-vision-v3.html (убрать комментарии, whitespace)
- [ ] Lazy load: D3.js грузить только при открытии Map
- [ ] Lazy load: charts рендерить только при открытии vault detail
- [ ] Проверить GZIP на Railway (должен быть автоматический)
- [ ] Оптимизировать /api/vaults response: убрать лишние поля

### Вечер: Mobile Check
- [ ] Проверить каждую страницу на 375px (iPhone SE)
- [ ] Проверить на 390px (iPhone 14)
- [ ] Fix сломанные layouts
- [ ] Проверить touch targets (кнопки ≥44px)

---

## Среда (19 марта) — Analytics & Data Quality

### Утро: Аудит данных
- [ ] Проверить все 23 vault'а: APR/TVL/Risk совпадают с HL?
- [ ] Проверить risk scores: адекватны ли? HLP должен быть low risk
- [ ] Проверить rankings: top 3 risk-adjusted — логично?
- [ ] Проверить Entry Intelligence: entry scores коррелируют с реальностью?

### День: Analytics Improvements
- [ ] Best Risk-Adjusted секция — проверить что показывает данные
- [ ] Vault detail page: проверить все графики (TVL, APR, PnL, Returns)
- [ ] Backtest calculator: проверить расчеты
- [ ] Compare page: проверить side-by-side корректность

### Вечер: Новые метрики
- [ ] Добавить Sharpe Ratio в vault detail (compute из daily returns)
- [ ] Добавить Max Drawdown визуализацию (bar в risk breakdown)
- [ ] Добавить Win Rate (% прибыльных дней) в vault stats

---

## Четверг (20 марта) — Telegram Bot + Whale Tracking

### Утро: Bot Improvements
- [ ] Добавить /deposit command → ссылка с Builder Code
- [ ] Улучшить /vaults — показывать risk score и entry label
- [ ] Добавить /risk {vault} — детальный risk breakdown
- [ ] Тестировать все команды

### День: Whale Tracking Foundation
- [ ] Endpoint: /api/vault/{id}/flows — deposit/withdraw history
- [ ] Определить threshold: whale = deposit > $50K
- [ ] Хранить flow events в hl_vault_flow_events
- [ ] Signal: WHALE_DEPOSIT, WHALE_WITHDRAW

### Вечер: Bot Alerts Enhancement
- [ ] Добавить whale alerts в бота
- [ ] Тестировать alert delivery (latency, formatting)
- [ ] Добавить inline button "View on VaultVision" с Builder Code link

---

## Пятница (21 марта) — Content & Growth

### Утро: Twitter Content Preparation
- [ ] Написать launch thread (10 твитов): "VaultVision is LIVE"
- [ ] Создать 5 vault card images (Figma/Canva)
- [ ] Подготовить daily format: "HL Vault Daily: Top 5 by risk-adjusted return"
- [ ] Создать Twitter account @VaultVision (если нет)

### День: SEO & Sharing
- [ ] Проверить OG meta tags на production
- [ ] Проверить Twitter Card preview (validator.twitter.com)
- [ ] Добавить vault-specific OG tags (при шаринге vault detail page)
- [ ] Проверить Google indexing (site:vaultvision.tech)

### Вечер: Documentation
- [ ] README.md — краткое описание для GitHub
- [ ] API docs: задокументировать V1 endpoints (примеры запросов/ответов)
- [ ] Обновить BUSINESS_LOGIC.md с результатами недели

---

## Суббота (22 марта) — Testing & Deploy

### Утро: End-to-End Testing
- [ ] Full user flow: landing → dashboard → vault detail → deposit click
- [ ] Builder Code: проверить что fee проходит
- [ ] Telegram Bot: full flow /start → /vaults → add watchlist → alert
- [ ] API: проверить все V1 endpoints (curl + jq)

### День: Monitoring Setup
- [ ] Добавить простой error logging (ошибки в отдельный файл/endpoint)
- [ ] Health check endpoint improvements (/api/v1/health с деталями)
- [ ] Uptime monitoring (UptimeRobot бесплатно)
- [ ] DB backup script (sqlite3 .backup)

### Вечер: Week Review
- [ ] Что сделано vs план
- [ ] Что перенести на следующую неделю
- [ ] Метрики: MAU, clicks, bot users
- [ ] Составить план на следующую неделю

---

## Приоритеты (если не успеваю всё)

### Must-Have (без этого не запускаемся):
1. ✅ Builder Code registration + deposit flow
2. ✅ Critical bug fixes (OG, vault count, BUILT FOR)
3. ✅ Mobile check (хотя бы dashboard)
4. ✅ Data quality audit (risk scores адекватны?)

### Should-Have (сильно улучшают продукт):
5. Performance optimization (lazy load)
6. Whale tracking foundation
7. Twitter launch thread
8. Bot /deposit command

### Nice-to-Have (если останется время):
9. Sharpe Ratio
10. SEO optimization
11. Monitoring setup
12. API documentation

---

## KPIs на конец недели

| Метрика | Target |
|---------|--------|
| Builder Code | Зарегистрирован, deposit flow работает |
| Critical bugs | 0 (все починены) |
| Site speed | <3 сек load time |
| Mobile | Dashboard работает на iPhone |
| Data accuracy | Risk scores match reality |
| Twitter | Account создан, launch thread готов |
| Bot | /deposit работает с Builder Code |

---

*План пересматривается ежедневно утром. Приоритеты могут меняться.*
