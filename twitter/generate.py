#!/usr/bin/env python3
"""Generate VaultVision tweets using Claude API + live vault data.

Content types:
  paper_update  - Paper trading strategy results vs BTC/HLP
  vault_spotlight - Weekly deep-dive on a vault
  build_update  - What's new in VaultVision
  market_alert  - Notable vault movements
"""

import sys
import os
import json
import sqlite3
import time
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'), override=True)

import anthropic

DB = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vaultvision.db')

STYLE_PROMPT = """You are ghostwriting tweets for @0xkayser, founder of VaultVision (vaultvision.tech) — a vault analytics platform for Hyperliquid.

VOICE & STYLE (match exactly):
- Builder tone: confident but not arrogant, data-driven, direct
- Short punchy sentences. No fluff. No disclaimers.
- Use line breaks for readability
- Numbers and data points are key — always include specific metrics
- Tag relevant accounts when mentioning vaults (@SystemicStratHL, @GrowiHF, @DoCryptoBred etc)
- End with CTA or insight, never "NFA" or "DYOR"
- NO emojis except sparingly (max 1 per tweet)
- NO hashtags
- English only
- Max 280 chars per tweet
- Reference vaultvision.tech naturally (not every tweet)

EXAMPLES OF GOOD TWEETS:
"APR is marketing. Edge is risk-adjusted decision quality."
"90% of vault depositors pick by APR. 90% lose to HLP. coincidence?"
"$2.4M peak PnL. Top-3 on Hyperliquid. Now closed. Good vaults close. New ones emerge."
"""


def get_vault_data():
    """Fetch current vault data from DB."""
    try:
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT pk, vault_name, tvl_usd, apr, pnl, roi, protocol, status
            FROM vaults WHERE tvl_usd > 50000 AND status = 'active'
            ORDER BY tvl_usd DESC LIMIT 25
        """).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"DB error: {e}")
        return []


def get_paper_trading_data():
    """Fetch paper trading results."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        import paper_trade as pt
        results = {}
        for sname in pt.ALL_STRATEGY_NAMES:
            state = pt.load_state(sname)
            strat = pt.STRATEGIES[sname]
            equity = state.get('cash', 10000)
            for p in state.get('positions', []):
                equity += p.get('capital', 0)
            ret = (equity - 10000) / 10000
            log = state.get('equity_log', [])
            peak = max((e['equity'] for e in log), default=10000)
            dd = (equity - peak) / peak if peak > 0 else 0
            results[sname] = {
                'name': strat['name'],
                'equity': equity,
                'return': ret,
                'max_dd': dd,
                'open_positions': len(state.get('positions', [])),
                'closed_trades': len(state.get('closed_trades', [])),
            }
        return results
    except Exception as e:
        print(f"Paper trading error: {e}")
        return {}


def get_vault_details(vault_pk):
    """Fetch detailed vault info from HL API."""
    try:
        resp = requests.post("https://api.hyperliquid.xyz/info",
                             json={"type": "vaultDetails", "vaultAddress": vault_pk}, timeout=10)
        return resp.json()
    except Exception:
        return {}


def generate(content_type, extra_context=""):
    """Generate tweet content using Claude."""
    client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

    # Build context based on content type
    context = ""

    if content_type == "paper_update":
        data = get_paper_trading_data()
        if data:
            lines = []
            for sname, d in sorted(data.items(), key=lambda x: -x[1]['return']):
                lines.append(f"  {d['name']}: ${d['equity']:,.0f} ({d['return']*100:+.1f}%) DD:{d['max_dd']*100:.1f}% | {d['open_positions']} open, {d['closed_trades']} closed")
            context = "Paper trading results (each strategy started with $10K):\n" + "\n".join(lines)
            context += "\n\nBenchmarks: check BTC and HLP performance for comparison"

        prompt = f"""Generate a single tweet (max 280 chars) about our paper trading strategy results.

{context}

Focus on: which strategy is winning, comparison vs just holding BTC, the edge of systematic vault selection.
Make it sound like a builder sharing real results, not a marketing post.
Include specific numbers.
Mention vaultvision.tech if it fits naturally."""

    elif content_type == "vault_spotlight":
        vaults = get_vault_data()
        # Pick an interesting vault (not HLP, high activity)
        interesting = [v for v in vaults if 'hyperliquidity' not in v['vault_name'].lower() and v['tvl_usd'] > 200000]
        if interesting:
            vault = interesting[0]  # TODO: rotate
            details = get_vault_details(vault['pk'])
            context = f"""Vault: {vault['vault_name']}
TVL: ${vault['tvl_usd']:,.0f}
APR: {vault['apr']:.1f}%
PnL: ${vault['pnl']:,.0f}
ROI: {vault['roi']:.1f}%
Leader fraction: {details.get('leaderFraction', '?')}
Positions: check from details"""

        prompt = f"""Generate a Vault Spotlight thread (3-4 tweets, JSON array of strings).

{context}

Structure:
1. Hook — the interesting angle about this vault (not just "here's a vault")
2. Strategy breakdown — what they do, leverage, positions
3. Risk analysis — drawdown, concentration, what could go wrong
4. Our take — is it a good entry? Mention vaultvision.tech for full analysis

Tag the vault manager if you know their handle.
Each tweet max 280 chars. Return ONLY a JSON array of strings."""

    elif content_type == "build_update":
        prompt = f"""Generate a single tweet (max 280 chars) about a VaultVision product update.

Recent features we shipped:
- Copy Trading (auto-copy vault positions to your account)
- One-Click Hedge (hedge vault exposure instantly)
- Paper Trading (7 strategies running in parallel, beating BTC)
- Admin Analytics dashboard
- Privacy-friendly analytics

{extra_context}

Pick ONE feature and make it sound exciting but grounded. Builder voice.
Not a launch announcement — more like "just shipped X, here's why it matters"."""

    elif content_type == "market_alert":
        vaults = get_vault_data()
        context = "Top vaults by TVL:\n"
        for v in vaults[:10]:
            context += f"  {v['vault_name']}: ${v['tvl_usd']:,.0f} TVL, {v['apr']:.1f}% APR\n"

        prompt = f"""Generate a single tweet (max 280 chars) about notable vault market movements.

{context}
{extra_context}

Focus on: what's moving, why it matters, what smart depositors should watch.
Data-driven, not hype."""

    else:
        prompt = extra_context or "Generate a general VaultVision tweet about vault analytics on Hyperliquid."

    # Call Claude
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        system=STYLE_PROMPT,
        messages=[{"role": "user", "content": prompt}]
    )

    response_text = message.content[0].text.strip()

    # Try parsing as JSON (for threads)
    try:
        parsed = json.loads(response_text)
        if isinstance(parsed, list):
            return {"type": "thread", "tweets": parsed}
    except json.JSONDecodeError:
        pass

    # Clean up — remove quotes if wrapped
    if response_text.startswith('"') and response_text.endswith('"'):
        response_text = response_text[1:-1]

    return {"type": "single", "text": response_text}


if __name__ == "__main__":
    content_type = sys.argv[1] if len(sys.argv) > 1 else "paper_update"
    extra = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else ""

    print(f"Generating: {content_type}")
    print("=" * 60)

    result = generate(content_type, extra)

    if result["type"] == "thread":
        for i, t in enumerate(result["tweets"]):
            print(f"\n[{i+1}] {t}")
            print(f"    ({len(t)} chars)")
        # Save thread to file
        with open("/tmp/vv_thread.json", "w") as f:
            json.dump(result["tweets"], f, indent=2)
        print(f"\nSaved to /tmp/vv_thread.json")
        print(f"Post with: python tweet.py --thread /tmp/vv_thread.json")
    else:
        print(result["text"])
        print(f"\n({len(result['text'])} chars)")
        print(f"\nPost with: python tweet.py '{result['text']}'")
