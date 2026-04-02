# VaultVision Content Plan — @0xkayser

## Weekly Schedule

| Day | Type | Content | Auto/Manual |
|-----|------|---------|-------------|
| Mon | Paper Update | Strategy results vs BTC/HLP | Auto-generate, manual post |
| Tue | Build in Public | What we shipped, what's next | Manual |
| Wed | Market Commentary | Vault movements, whale flows | Auto-generate |
| Thu | Paper Update | Mid-week strategy check | Auto-generate, manual post |
| Fri | Vault Spotlight | Deep-dive thread (3-4 tweets) | Auto-generate, manual review |
| Sat | Engagement | Reply to vault/HL tweets | Semi-auto (approve replies) |
| Sun | Off | — | — |

## Content Types

### 1. Paper Trading Update (2x/week)
- Best: `python twitter/generate.py paper_update`
- Compare strategies vs BTC hold and HLP
- Specific numbers: return %, max DD, win rate
- "Building in public" angle

### 2. Vault Spotlight (1x/week, Friday)
- Thread: `python twitter/generate.py vault_spotlight`
- Pick interesting vault (rotate weekly)
- Data: TVL, PnL, positions, risk, leader stake
- Tag vault manager
- End with "full analysis on vaultvision.tech"

### 3. Build in Public (1x/week)
- What we shipped this week
- `python twitter/generate.py build_update "description"`
- Features, insights, metrics

### 4. Market Commentary (1x/week)
- `python twitter/generate.py market_alert "context about what happened"`
- Big drawdowns, vault closures, whale movements
- Data-driven hot takes

### 5. Engagement (daily)
- `python twitter/engage.py engage`
- Like 5 relevant vault/HL tweets
- Reply to 3 high-quality discussions
- All replies AI-generated, manually approved

## Commands Cheat Sheet

```bash
# Generate content
python twitter/generate.py paper_update
python twitter/generate.py vault_spotlight
python twitter/generate.py build_update "shipped copy trading"
python twitter/generate.py market_alert "BredoStrategy dropped 20%"

# Post
python twitter/tweet.py "tweet text"
python twitter/tweet.py --thread /tmp/vv_thread.json
python twitter/tweet.py --reply TWEET_ID "reply text"

# Engage
python twitter/engage.py engage      # search + like + reply
python twitter/engage.py mentions    # check mentions
python twitter/engage.py reply ID    # reply to specific tweet
```

## Voice Guidelines
- Builder, not marketer
- Data > opinions
- Short sentences, line breaks
- Tag vault managers when relevant
- No emojis (max 1), no hashtags, no "NFA/DYOR"
- English only
- vaultvision.tech naturally, not every tweet
