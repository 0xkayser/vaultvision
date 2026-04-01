#!/usr/bin/env python3
"""
VaultVision Paper Trading Engine — Multi-Strategy

Runs 6 strategies in parallel, each with independent $10K portfolio.
Strategies ported from backtest_v4_robust.py walk-forward validation.

Commands:
  python3 paper_trade.py              — run daily for ALL strategies
  python3 paper_trade.py --compare    — side-by-side comparison table
  python3 paper_trade.py --strategy X — run/show single strategy
  python3 paper_trade.py --status     — show current portfolio(s)
  python3 paper_trade.py --reset      — reset all portfolios to $10K
  python3 paper_trade.py --history    — show equity history
"""

import sqlite3
import json
import math
import datetime
import argparse
import os
import sys
import requests

DB = "vaultvision.db"
LEADER_COMMISSION = 0.10
INITIAL_CAPITAL = 10_000

# Risk limits (shared across all strategies)
MAX_DRAWDOWN_STOP = -0.13
MAX_LOSS_PER_POSITION = -0.15
MAX_ALLOCATION_PCT = 0.25

# ═══════════════════════════════════════════════════════════════════════
# NEW RISK FILTERS (v2 — based on research)
# ═══════════════════════════════════════════════════════════════════════
WHALE_CONCENTRATION_MAX = 0.70   # Skip vaults where top1 depositor > 70%
WHALE_OUTFLOW_WARNING = -50_000  # Warn if 7d whale outflow > $50K
STAGNATION_DAYS = 5              # Exit if price moved < 0.5% in N days
STAGNATION_THRESHOLD = 0.005     # Min movement to not be "stagnant"
VOLATILITY_LOOKBACK = 14         # Days for vol-adjusted sizing
HALF_KELLY_FRACTION = 0.5        # Use Half Kelly for sizing
REENTRY_COOLDOWN_DAYS = 7        # Don't re-enter vault within N days of exit
MIN_VAULT_AGE_DAYS = 30          # Don't enter vaults younger than 30 days

# ═══════════════════════════════════════════════════════════════════════
# STRATEGY REGISTRY
# ═══════════════════════════════════════════════════════════════════════

STRATEGIES = {
    "optimal": {
        "name": "Optimal Combo",
        "hold_days": 14,
        "max_pos": 5,
        "description": "5-factor confidence scoring (TVL, accel, value, gap, leverage)",
        "verdict": "ROBUST (0.6x)",
        "color": "#00ff88",
    },
    "composite": {
        "name": "Composite Leading",
        "hold_days": 14,
        "max_pos": 3,
        "description": "Multi-factor: TVL growth + exposure/value + leverage safety",
        "verdict": "To validate",
        "color": "#00d4ff",
    },
    "smart_money": {
        "name": "Smart Money",
        "hold_days": 14,
        "max_pos": 3,
        "description": "TVL inflow > 5% with stagnant price < 2%",
        "verdict": "To validate",
        "color": "#ff6b6b",
    },
    "risk_off": {
        "name": "Risk-Off Rotation",
        "hold_days": 14,
        "max_pos": 5,
        "rebalance_days": 7,
        "description": "Dynamic rebalancing by vault strength score",
        "verdict": "To validate",
        "color": "#ffd93d",
    },
    "eq_gap": {
        "name": "Equity-Price Gap",
        "hold_days": 14,
        "max_pos": 3,
        "description": "TVL grows faster than vault price (divergence)",
        "verdict": "To validate",
        "color": "#c084fc",
    },
    "tvl_accel": {
        "name": "TVL Acceleration",
        "hold_days": 14,
        "max_pos": 3,
        "description": "TVL growth rate accelerating (control — was OVERFIT in backtest)",
        "verdict": "OVERFIT (7.3x)",
        "color": "#ff8c42",
    },
}

ALL_STRATEGY_NAMES = list(STRATEGIES.keys())


def state_file_for(strategy_name):
    """Get state file path for a strategy."""
    if strategy_name == "optimal":
        return "paper_trading_state.json"  # backward compat
    return f"paper_state_{strategy_name}.json"


def now_ts():
    """Use the latest data timestamp, not wall clock, to avoid stale-data gaps."""
    try:
        conn = sqlite3.connect(DB)
        r = conn.execute("SELECT MAX(ts) FROM pnl_history").fetchone()
        conn.close()
        if r and r[0]:
            return int(r[0])
    except Exception:
        pass
    return int(datetime.datetime.utcnow().timestamp())


def today_str():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d")


def ts_fmt(ts):
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


# ═══════════════════════════════════════════════════════════════════════
# STATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════

def new_state():
    return {
        "initial_capital": INITIAL_CAPITAL,
        "cash": INITIAL_CAPITAL,
        "positions": [],
        "closed_trades": [],
        "equity_log": [{"date": today_str(), "equity": INITIAL_CAPITAL, "ts": now_ts()}],
        "start_date": today_str(),
        "total_trades": 0,
        "total_slippage": 0,
        "alerts": [],
        "status": "ACTIVE",
    }


def load_state(strategy_name="optimal"):
    sf = state_file_for(strategy_name)
    if os.path.exists(sf):
        with open(sf) as f:
            return json.load(f)
    return new_state()


def save_state(state, strategy_name="optimal"):
    sf = state_file_for(strategy_name)
    with open(sf, "w") as f:
        json.dump(state, f, indent=2, default=str)


# ═══════════════════════════════════════════════════════════════════════
# DATA — LIVE FROM DATABASE
# ═══════════════════════════════════════════════════════════════════════

def load_live_vaults():
    """Load current vault data from live database (with exposure + equity series)."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    vault_rows = conn.execute("""
        SELECT v.pk, v.vault_name, v.protocol, v.tvl_usd, v.apr, v.status,
               COUNT(DISTINCT p.ts) as pnl_points
        FROM vaults v
        JOIN pnl_history p ON p.vault_pk = v.pk
        GROUP BY v.pk
        HAVING pnl_points >= 50
        ORDER BY pnl_points DESC
    """).fetchall()

    vaults = {}
    for v in vault_rows:
        pk = v["pk"]

        pnl = conn.execute(
            "SELECT ts, account_value FROM pnl_history WHERE vault_pk=? ORDER BY ts ASC",
            (pk,),
        ).fetchall()
        values = [(r["ts"], float(r["account_value"]))
                  for r in pnl if r["account_value"] and float(r["account_value"]) > 0]

        snaps = conn.execute(
            "SELECT ts, tvl_usd FROM snapshots WHERE vault_pk=? ORDER BY ts ASC",
            (pk,),
        ).fetchall()
        tvl_series = [(s["ts"], float(s["tvl_usd"])) for s in snaps if s["tvl_usd"]]

        # Load leverage, exposure, equity from hl_vault_state
        states = conn.execute(
            "SELECT ts, leverage_effective, gross_exposure_usd, equity_usd "
            "FROM hl_vault_state WHERE vault_id=? ORDER BY ts ASC",
            (pk,),
        ).fetchall()
        leverage_series = []
        exposure_series = []
        equity_series = []
        for s in states:
            if s["leverage_effective"] is not None:
                try:
                    leverage_series.append((s["ts"], float(s["leverage_effective"])))
                except (ValueError, TypeError):
                    pass
            if s["gross_exposure_usd"] is not None:
                try:
                    exposure_series.append((s["ts"], float(s["gross_exposure_usd"])))
                except (ValueError, TypeError):
                    pass
            if s["equity_usd"] is not None:
                try:
                    equity_series.append((s["ts"], float(s["equity_usd"])))
                except (ValueError, TypeError):
                    pass

        if len(values) < 10:
            continue

        # Load whale concentration & flow risk from latest hl_vault_state
        whale_row = conn.execute(
            "SELECT concentration_top1, concentration_top3, whale_outflow_7d, net_flow_7d, liq_risk "
            "FROM hl_vault_state WHERE vault_id=? ORDER BY ts DESC LIMIT 1",
            (pk,),
        ).fetchone()
        conc_top1 = float(whale_row["concentration_top1"]) if whale_row and whale_row["concentration_top1"] else 0
        conc_top3 = float(whale_row["concentration_top3"]) if whale_row and whale_row["concentration_top3"] else 0
        whale_outflow = float(whale_row["whale_outflow_7d"]) if whale_row and whale_row["whale_outflow_7d"] else 0
        net_flow_7d = float(whale_row["net_flow_7d"]) if whale_row and whale_row["net_flow_7d"] else 0
        liq_risk_raw = whale_row["liq_risk"] if whale_row and whale_row["liq_risk"] else "low"
        liq_risk = {"low": 0.0, "moderate": 0.3, "high": 0.8}.get(str(liq_risk_raw).lower(), 0.0)
        try:
            liq_risk = float(liq_risk_raw) if isinstance(liq_risk_raw, (int, float)) else liq_risk
        except (ValueError, TypeError):
            pass

        vaults[pk] = {
            "pk": pk,
            "name": v["vault_name"][:40],
            "protocol": v["protocol"],
            "status": v["status"],
            "tvl": v["tvl_usd"] or 0,
            "apr": v["apr"] or 0,
            "values": values,
            "tvl_series": tvl_series,
            "leverage_series": leverage_series,
            "exposure_series": exposure_series,
            "equity_series": equity_series,
            "current_val": values[-1][1] if values else 0,
            "last_ts": values[-1][0] if values else 0,
            # Risk data (v2)
            "concentration_top1": conc_top1,
            "concentration_top3": conc_top3,
            "whale_outflow_7d": whale_outflow,
            "net_flow_7d": net_flow_7d,
            "liq_risk": liq_risk,
        }

    conn.close()

    # Refresh current_val from HL API for accuracy (DB may be stale)
    updated = 0
    for pk in list(vaults.keys()):
        try:
            resp = requests.post("https://api.hyperliquid.xyz/info",
                                 json={"type": "vaultDetails", "vaultAddress": pk}, timeout=10)
            if resp.status_code == 200:
                d = resp.json()
                portfolio = d.get("portfolio")
                if isinstance(portfolio, list) and len(portfolio) > 0:
                    # portfolio[0] = ['day', {accountValueHistory: [...]}]
                    day_entry = portfolio[0]
                    if isinstance(day_entry, list) and len(day_entry) > 1 and isinstance(day_entry[1], dict):
                        hist = day_entry[1].get("accountValueHistory", [])
                        if hist:
                            latest_av = float(hist[-1][1])
                            if latest_av > 0:
                                vaults[pk]["current_val"] = latest_av
                                updated += 1
        except Exception:
            pass
    if updated:
        print(f"[PAPER] Refreshed {updated}/{len(vaults)} vault values from HL API")

    return vaults


def get_val(series, target_ts, max_gap=86400):
    """Get most recent value AT or BEFORE target_ts."""
    if not series:
        return None
    lo, hi = 0, len(series) - 1
    result = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if series[mid][0] <= target_ts:
            result = series[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    if result and (target_ts - result[0]) <= max_gap:
        return result[1]
    return None


def growth_rate(series, ts, lookback_sec):
    val_now = get_val(series, ts, max_gap=86400 * 2)
    val_prev = get_val(series, ts - lookback_sec, max_gap=86400 * 2)
    if val_now and val_prev and val_prev > 0:
        return (val_now - val_prev) / val_prev
    return None


def hl_slippage(vault_tvl, amount):
    if vault_tvl <= 0:
        return 0.005
    impact = 0.001 * math.sqrt(amount / vault_tvl)
    return min(impact, 0.02)


# ═══════════════════════════════════════════════════════════════════════
# RISK FILTERS (v2) — pre-scoring vault health checks
# ═══════════════════════════════════════════════════════════════════════

def check_vault_health(v, state=None):
    """Pre-filter: returns (is_healthy, warnings) before scoring.
    Blocks entry if critical risk detected."""
    warnings = []
    block = False

    # Vault status filter — skip non-active vaults
    if v.get("status") and v["status"] not in ("active", None, ""):
        warnings.append(f"⚠️ Vault status: {v['status']}")
        block = True

    # Vault age filter — skip freshly deployed vaults (exploit risk)
    if v.get("values") and len(v["values"]) >= 2:
        vault_age_days = (v["values"][-1][0] - v["values"][0][0]) / 86400
        if vault_age_days < MIN_VAULT_AGE_DAYS:
            warnings.append(f"⚠️ Too young: {vault_age_days:.0f}d (min {MIN_VAULT_AGE_DAYS}d)")
            block = True

    # Whale concentration — top1 depositor owns too much
    if v.get("concentration_top1", 0) > WHALE_CONCENTRATION_MAX:
        warnings.append(f"⚠️ Whale risk: top1 depositor = {v['concentration_top1']*100:.0f}%")
        block = True

    # Large whale outflow — smart money leaving
    if v.get("whale_outflow_7d", 0) < WHALE_OUTFLOW_WARNING:
        warnings.append(f"⚠️ Whale exodus: ${v['whale_outflow_7d']:,.0f} outflow 7d")
        block = True

    # Liquidation risk
    if v.get("liq_risk", 0) > 0.5:
        warnings.append(f"⚠️ High liq risk: {v['liq_risk']:.2f}")
        block = True

    # Re-entry cooldown — don't re-enter vault recently exited
    if state and state.get("closed_trades"):
        pk = v.get("pk")
        ts = now_ts()
        for t in reversed(state["closed_trades"][-20:]):
            if t.get("vault_name") == v.get("name"):
                exit_date = t.get("exit_date", "")
                try:
                    exit_ts = datetime.datetime.strptime(exit_date, "%Y-%m-%d").timestamp()
                    days_since = (ts - exit_ts) / 86400
                    if days_since < REENTRY_COOLDOWN_DAYS:
                        warnings.append(f"⚠️ Cooldown: exited {days_since:.0f}d ago (min {REENTRY_COOLDOWN_DAYS}d)")
                        block = True
                except (ValueError, TypeError):
                    pass
                break

    return not block, warnings


def check_stagnation(v, ts, pos):
    """Check if position value has been stagnant for too long."""
    day = 86400
    # Check if price moved less than threshold over stagnation period
    val_now = get_val(v["values"], ts, day * 2)
    val_stag = get_val(v["values"], ts - STAGNATION_DAYS * day, day * 2)

    if val_now and val_stag and val_stag > 0:
        move = abs(val_now - val_stag) / val_stag
        if move < STAGNATION_THRESHOLD:
            held = (ts - pos["entry_ts"]) / day
            if held >= STAGNATION_DAYS:
                return [f"Stagnation exit: moved {move*100:.2f}% in {STAGNATION_DAYS}d (threshold: {STAGNATION_THRESHOLD*100:.1f}%)"]
    return []


def compute_volatility(values, lookback_days=14):
    """Compute annualized daily volatility from value series."""
    day = 86400
    if len(values) < lookback_days + 1:
        return None

    # Get daily returns for last N days
    recent = values[-(lookback_days + 1):]
    returns = []
    for i in range(1, len(recent)):
        if recent[i-1][1] > 0:
            ret = (recent[i][1] - recent[i-1][1]) / recent[i-1][1]
            returns.append(ret)

    if len(returns) < 5:
        return None

    mean = sum(returns) / len(returns)
    var = sum((r - mean)**2 for r in returns) / len(returns)
    daily_vol = math.sqrt(var)
    return daily_vol * math.sqrt(365)  # annualized


def vol_adjusted_allocation(state, vault, max_pos):
    """Half-Kelly inspired position sizing: lower allocation for higher vol."""
    n_positions = len(state["positions"])
    if n_positions >= max_pos:
        return 0

    base_alloc = min(state["cash"] * MAX_ALLOCATION_PCT,
                     state["cash"] / (max_pos - n_positions))

    vol = compute_volatility(vault["values"], VOLATILITY_LOOKBACK)
    if vol is not None and vol > 0:
        # Scale inversely with volatility. Base = 30% annual vol.
        # Higher vol → smaller position, lower vol → larger position
        vol_scale = min(0.30 / vol, 1.5)  # cap at 1.5x base
        vol_scale = max(vol_scale, 0.3)    # floor at 0.3x base
        adjusted = base_alloc * vol_scale * HALF_KELLY_FRACTION
        # But never more than base allocation
        return min(adjusted, base_alloc)

    # No vol data — use conservative 60% of base
    return base_alloc * 0.6


# ═══════════════════════════════════════════════════════════════════════
# HLP BENCHMARK — passive comparison
# ═══════════════════════════════════════════════════════════════════════

def get_hlp_benchmark(vaults):
    """Get HLP vault performance as benchmark."""
    for pk, v in vaults.items():
        if "hyperliquidity provider" in v["name"].lower() or "hlp" in v["name"].lower():
            if len(v["values"]) >= 2:
                first_val = v["values"][0][1]
                last_val = v["values"][-1][1]
                if first_val > 0:
                    return {
                        "name": v["name"],
                        "pk": pk,
                        "total_return": (last_val - first_val) / first_val,
                        "current_val": last_val,
                        "values": v["values"],
                    }
    return None


# ═══════════════════════════════════════════════════════════════════════
# SCORING FUNCTIONS — one per strategy
# Each returns (score, reasons) where score >= threshold = enter
# ═══════════════════════════════════════════════════════════════════════

def score_optimal(v, ts):
    """5-factor confidence scoring. Threshold: >= 2.5"""
    day = 86400
    lookback_short = 3 * day
    lookback_long = 14 * day

    confidence = 0
    reasons = []

    tvl_g_long = growth_rate(v["tvl_series"], ts, lookback_long) if v["tvl_series"] else None
    tvl_g_short = growth_rate(v["tvl_series"], ts, lookback_short) if v["tvl_series"] else None

    if tvl_g_long is not None and tvl_g_long > 0:
        confidence += 1
        reasons.append(f"TVL 14d: +{tvl_g_long*100:.1f}%")
    if tvl_g_short is not None and tvl_g_long is not None and tvl_g_short > tvl_g_long:
        confidence += 1
        reasons.append(f"TVL accelerating (3d: +{tvl_g_short*100:.1f}%)")

    val_g_short = growth_rate(v["values"], ts, lookback_short)
    val_g_long = growth_rate(v["values"], ts, lookback_long)

    if val_g_short is not None and val_g_short > 0:
        confidence += 1
        reasons.append(f"Value 3d: +{val_g_short*100:.1f}%")
    if val_g_long is not None and val_g_long > 0:
        confidence += 0.5
        reasons.append(f"Value 14d: +{val_g_long*100:.1f}%")

    if (tvl_g_short is not None and val_g_short is not None
            and tvl_g_short > 0.03 and val_g_short < tvl_g_short):
        confidence += 1
        reasons.append(f"TVL leading price (gap: {(tvl_g_short - val_g_short)*100:.1f}%)")

    if v["leverage_series"]:
        lev = get_val(v["leverage_series"], ts, day * 2)
        if lev is not None:
            if 0.5 <= lev <= 3.0:
                confidence += 0.5
                reasons.append(f"Leverage safe: {lev:.1f}x")
            elif lev > 5.0:
                confidence -= 1
                reasons.append(f"Leverage HIGH: {lev:.1f}x")

    # v2: whale outflow penalty
    if v.get("whale_outflow_7d", 0) < -20_000:
        confidence -= 0.5
        reasons.append(f"Whale outflow: ${v['whale_outflow_7d']:,.0f}")

    # v2: net flow boost
    if v.get("net_flow_7d", 0) > 50_000:
        confidence += 0.5
        reasons.append(f"Strong inflow: +${v['net_flow_7d']:,.0f}")

    return confidence, reasons


# Keep old name for backward compat (used by API signals endpoint)
compute_vault_confidence = score_optimal


def score_tvl_accel(v, ts):
    """TVL acceleration strategy. Threshold: > 0 (binary enter/skip)."""
    day = 86400
    lookback = 7 * day

    if not v["tvl_series"]:
        return -1, []

    growth_now = growth_rate(v["tvl_series"], ts, lookback)
    growth_prev = growth_rate(v["tvl_series"], ts - day, lookback)

    if growth_now is None or growth_prev is None:
        return -1, []

    acceleration = growth_now - growth_prev
    reasons = []

    if acceleration > 0.05 and growth_now > 0:
        score = acceleration * 10  # higher accel = higher score
        reasons.append(f"TVL accel: {acceleration*100:.1f}% (growth: {growth_now*100:.1f}%)")
        return score, reasons

    return -1, []


def score_eq_gap(v, ts):
    """Equity-price gap. Threshold: > 0."""
    day = 86400
    lookback = 7 * day

    if not v.get("equity_series") or len(v["equity_series"]) < 5:
        return -1, []

    eq_growth = growth_rate(v["equity_series"], ts, lookback)
    val_growth = growth_rate(v["values"], ts, lookback)

    if eq_growth is None or val_growth is None:
        return -1, []

    gap = eq_growth - val_growth
    if gap > 0.03 and eq_growth > 0:
        reasons = [f"Equity-price gap: {gap*100:.1f}% (eq: +{eq_growth*100:.1f}%, val: {val_growth*100:+.1f}%)"]
        return gap * 10, reasons

    return -1, []


def score_composite(v, ts):
    """Composite multi-factor. Threshold: >= 2."""
    day = 86400
    lookback = 7 * day

    score = 0
    reasons = []

    tvl_g = growth_rate(v["tvl_series"], ts, lookback) if v["tvl_series"] else None
    if tvl_g is not None and tvl_g > 0.03:
        score += 1
        reasons.append(f"TVL growth: +{tvl_g*100:.1f}%")

    if v.get("exposure_series") and len(v["exposure_series"]) > 3:
        exp_g = growth_rate(v["exposure_series"], ts, lookback)
        if exp_g is not None and exp_g > 0.05:
            score += 1
            reasons.append(f"Exposure growth: +{exp_g*100:.1f}%")
    else:
        val_g = growth_rate(v["values"], ts, lookback)
        if val_g is not None and val_g > 0.02:
            score += 1
            reasons.append(f"Value growth: +{val_g*100:.1f}%")

    if v["leverage_series"]:
        lev = get_val(v["leverage_series"], ts, day * 2)
        if lev is not None and 0 < lev <= 5.0:
            score += 1
            reasons.append(f"Leverage OK: {lev:.1f}x")
    else:
        score += 0.5

    return score, reasons


def score_smart_money(v, ts):
    """Smart money: TVL inflow with stagnant price. Threshold: > 0."""
    day = 86400
    lookback = 7 * day

    if not v["tvl_series"] or len(v["tvl_series"]) < 3:
        return -1, []

    tvl_g = growth_rate(v["tvl_series"], ts, lookback)
    val_g = growth_rate(v["values"], ts, lookback)

    if tvl_g is None or val_g is None:
        return -1, []

    if tvl_g > 0.05 and val_g < 0.02:
        reasons = [f"Smart money: TVL +{tvl_g*100:.1f}% but price {val_g*100:+.1f}%"]
        return tvl_g * 10, reasons

    return -1, []


def score_risk_off(v, ts):
    """Risk-off strength score. Returns continuous score."""
    day = 86400
    lookback = 7 * day

    val_g = growth_rate(v["values"], ts, lookback)
    tvl_g = growth_rate(v["tvl_series"], ts, lookback) if v["tvl_series"] else None

    if val_g is None:
        return -1, []

    score = 0
    reasons = []
    min_growth = 0.01

    if val_g > min_growth:
        score += val_g * 10
        reasons.append(f"Value momentum: +{val_g*100:.1f}%")
    else:
        score -= 1

    if tvl_g is not None:
        if tvl_g > min_growth:
            score += tvl_g * 5
            reasons.append(f"TVL momentum: +{tvl_g*100:.1f}%")
        elif tvl_g < -min_growth:
            score -= 2
            reasons.append(f"TVL declining: {tvl_g*100:.1f}%")

    return score, reasons


# Map strategy name -> (scoring_fn, entry_threshold)
SCORING_FUNCTIONS = {
    "optimal":     (score_optimal, 2.5),
    "composite":   (score_composite, 2.0),
    "smart_money": (score_smart_money, 0.0),
    "risk_off":    (score_risk_off, 0.0),
    "eq_gap":      (score_eq_gap, 0.0),
    "tvl_accel":   (score_tvl_accel, 0.0),
}


# ═══════════════════════════════════════════════════════════════════════
# EXIT SIGNALS
# ═══════════════════════════════════════════════════════════════════════

def check_exit_signal(v, ts, pos, hold_days=14):
    """Check if a position should be exited."""
    day = 86400
    lookback_short = 3 * day
    reasons = []

    held = (ts - pos["entry_ts"]) / day
    if held >= hold_days:
        reasons.append(f"Hold timeout ({held:.0f}d >= {hold_days}d)")

    tvl_g = growth_rate(v["tvl_series"], ts, lookback_short) if v["tvl_series"] else None
    if tvl_g is not None and tvl_g < -0.05:
        reasons.append(f"TVL dropping: {tvl_g*100:.1f}%")

    val_g = growth_rate(v["values"], ts, lookback_short)
    if val_g is not None and val_g < -0.03:
        reasons.append(f"Value dropping: {val_g*100:.1f}%")

    current_val = v["current_val"]
    if current_val and pos["entry_val"] > 0:
        pnl_pct = (current_val - pos["entry_val"]) / pos["entry_val"]
        if pnl_pct < MAX_LOSS_PER_POSITION:
            reasons.append(f"Stop-loss hit: {pnl_pct*100:.1f}%")

    # v2: stagnation exit — exit if barely moved in N days
    stag_reasons = check_stagnation(v, ts, pos)
    reasons.extend(stag_reasons)

    # v2: whale exodus exit — if big whale outflow detected while holding
    if v.get("whale_outflow_7d", 0) < WHALE_OUTFLOW_WARNING:
        reasons.append(f"Whale exodus: ${v['whale_outflow_7d']:,.0f} outflow")

    return reasons


def check_exit_risk_off(v, ts, pos):
    """Risk-off specific: exit when strength score drops below 0."""
    reasons = check_exit_signal(v, ts, pos, hold_days=14)
    score, _ = score_risk_off(v, ts)
    if score < 0:
        reasons.append(f"Risk-off: strength score negative ({score:.1f})")
    return reasons


def check_exit_eq_gap(v, ts, pos):
    """EQ gap specific: exit when gap turns negative."""
    reasons = check_exit_signal(v, ts, pos, hold_days=14)
    day = 86400
    lookback = 7 * day
    if v.get("equity_series"):
        eq_g = growth_rate(v["equity_series"], ts, lookback)
        val_g = growth_rate(v["values"], ts, lookback)
        if eq_g is not None and val_g is not None:
            gap = eq_g - val_g
            if gap < -0.02:
                reasons.append(f"Gap turned negative: {gap*100:.1f}%")
    return reasons


EXIT_FUNCTIONS = {
    "optimal":     lambda v, ts, pos: check_exit_signal(v, ts, pos, 14),
    "composite":   lambda v, ts, pos: check_exit_signal(v, ts, pos, 14),
    "smart_money": lambda v, ts, pos: check_exit_signal(v, ts, pos, 14),
    "risk_off":    check_exit_risk_off,
    "eq_gap":      check_exit_eq_gap,
    "tvl_accel":   lambda v, ts, pos: check_exit_signal(v, ts, pos, 14),
}


# ═══════════════════════════════════════════════════════════════════════
# PORTFOLIO OPERATIONS
# ═══════════════════════════════════════════════════════════════════════

def enter_position(state, vault, ts, max_pos=5, use_vol_sizing=True):
    """Paper-enter a vault position with optional vol-adjusted sizing."""
    n_positions = len(state["positions"])
    if n_positions >= max_pos:
        return None

    for p in state["positions"]:
        if p["vault_pk"] == vault["pk"]:
            return None

    # v2: vol-adjusted position sizing (Half Kelly)
    if use_vol_sizing:
        alloc = vol_adjusted_allocation(state, vault, max_pos)
    else:
        slots_left = max_pos - n_positions
        alloc = min(state["cash"] * MAX_ALLOCATION_PCT, state["cash"] / slots_left)

    if alloc < 50:
        return None

    slip = hl_slippage(vault["tvl"], alloc)
    alloc_after = alloc * (1 - slip)

    pos = {
        "vault_pk": vault["pk"],
        "vault_name": vault["name"],
        "entry_val": vault["current_val"],
        "capital": alloc_after,
        "raw_alloc": alloc,
        "entry_ts": ts,
        "entry_date": today_str(),
        "slippage": alloc * slip,
    }
    state["positions"].append(pos)
    state["cash"] -= alloc
    state["total_trades"] += 1
    state["total_slippage"] += alloc * slip

    return pos


def exit_position(state, pos_idx, vault, ts, reasons):
    """Paper-exit a vault position."""
    pos = state["positions"][pos_idx]
    current_val = vault["current_val"]

    if current_val and pos["entry_val"] > 0:
        growth = (current_val - pos["entry_val"]) / pos["entry_val"]
        net = growth * (1 - LEADER_COMMISSION) if growth > 0 else growth
        returned = pos["capital"] * (1 + net)
    else:
        returned = pos["capital"]
        growth = 0

    slip = hl_slippage(vault["tvl"], returned)
    returned_after = returned * (1 - slip)

    state["cash"] += returned_after
    state["total_trades"] += 1
    state["total_slippage"] += returned * slip

    pnl = returned_after - pos["raw_alloc"]
    held_days = (ts - pos["entry_ts"]) / 86400
    state["closed_trades"].append({
        "vault_name": pos["vault_name"],
        "entry_date": pos["entry_date"],
        "exit_date": today_str(),
        "held_days": round(held_days, 1),
        "capital_in": pos["raw_alloc"],
        "capital_out": returned_after,
        "pnl": pnl,
        "pnl_pct": (pnl / pos["raw_alloc"]) * 100 if pos["raw_alloc"] > 0 else 0,
        "exit_reasons": reasons,
    })

    state["positions"].pop(pos_idx)
    return pnl


def mark_to_market(state, vaults):
    """Compute current portfolio equity."""
    total = state["cash"]
    for pos in state["positions"]:
        pk = pos["vault_pk"]
        if pk in vaults:
            v = vaults[pk]
            current_val = v["current_val"]
            if current_val and pos["entry_val"] > 0:
                growth = (current_val - pos["entry_val"]) / pos["entry_val"]
                net = growth * (1 - LEADER_COMMISSION) if growth > 0 else growth
                total += pos["capital"] * (1 + net)
            else:
                total += pos["capital"]
        else:
            total += pos["capital"]
    return total


def check_drawdown_stop(state, current_equity):
    if not state["equity_log"]:
        return False
    peak = max(e["equity"] for e in state["equity_log"])
    if peak <= 0:
        return False
    dd = (current_equity - peak) / peak
    return dd < MAX_DRAWDOWN_STOP


# ═══════════════════════════════════════════════════════════════════════
# DAILY RUN — per strategy
# ═══════════════════════════════════════════════════════════════════════

def run_daily_strategy(state, strategy_name, vaults=None):
    """Run daily signal check for a single strategy."""
    ts = now_ts()
    if vaults is None:
        vaults = load_live_vaults()

    if not vaults:
        return state, [], 0, vaults

    strat = STRATEGIES[strategy_name]
    max_pos = strat["max_pos"]
    hold_days = strat["hold_days"]
    score_fn, threshold = SCORING_FUNCTIONS[strategy_name]
    exit_fn = EXIT_FUNCTIONS[strategy_name]

    actions = []

    # ── CHECK EXITS FIRST ──
    exits_to_do = []
    for i, pos in enumerate(state["positions"]):
        pk = pos["vault_pk"]
        if pk not in vaults:
            exits_to_do.append((i, ["Vault no longer in database"]))
            continue
        exit_reasons = exit_fn(vaults[pk], ts, pos)
        if exit_reasons:
            exits_to_do.append((i, exit_reasons))

    for idx, reasons in sorted(exits_to_do, key=lambda x: x[0], reverse=True):
        pos = state["positions"][idx]
        pk = pos["vault_pk"]
        v = vaults.get(pk)
        if v:
            pnl = exit_position(state, idx, v, ts, reasons)
            actions.append(("EXIT", pos["vault_name"], pnl, reasons))

    # ── CHECK ENTRIES ──
    if state["status"] == "ACTIVE" and len(state["positions"]) < max_pos:
        candidates = []
        held_pks = {p["vault_pk"] for p in state["positions"]}

        # Risk-off has special rebalance logic
        if strategy_name == "risk_off":
            rebalance_days = strat.get("rebalance_days", 7)
            days_active = len(state["equity_log"])
            if days_active % rebalance_days != 0 and len(state["positions"]) > 0:
                # Not a rebalance day and we have positions, skip entries
                pass
            else:
                for pk, v in vaults.items():
                    if pk in held_pks:
                        continue
                    # v2: pre-filter unhealthy vaults
                    healthy, health_warns = check_vault_health(v, state)
                    if not healthy:
                        continue
                    score, reasons = score_fn(v, ts)
                    if score > threshold:
                        reasons.extend(health_warns)
                        candidates.append((pk, score, reasons))
        else:
            for pk, v in vaults.items():
                if pk in held_pks:
                    continue
                # v2: pre-filter unhealthy vaults
                healthy, health_warns = check_vault_health(v, state)
                if not healthy:
                    continue
                score, reasons = score_fn(v, ts)
                if score >= threshold:
                    reasons.extend(health_warns)
                    candidates.append((pk, score, reasons))

        candidates.sort(key=lambda x: x[1], reverse=True)

        for pk, conf, reasons in candidates[:max_pos - len(state["positions"])]:
            pos = enter_position(state, vaults[pk], ts, max_pos=max_pos)
            if pos:
                actions.append(("ENTER", vaults[pk]["name"], conf, reasons))

    # ── MARK TO MARKET ──
    equity = mark_to_market(state, vaults)

    if state["equity_log"] and state["equity_log"][-1]["date"] == today_str():
        state["equity_log"][-1]["equity"] = equity
        state["equity_log"][-1]["ts"] = ts
    else:
        state["equity_log"].append({"date": today_str(), "equity": equity, "ts": ts})

    # ── DRAWDOWN CHECK ──
    if check_drawdown_stop(state, equity):
        state["status"] = "STOPPED"
        state["alerts"].append({
            "date": today_str(),
            "type": "DRAWDOWN_STOP",
            "message": f"Portfolio DD exceeded {MAX_DRAWDOWN_STOP*100:.0f}%. Auto-stopped.",
            "equity": equity,
        })

    return state, actions, equity, vaults


# Keep backward compat name
def run_daily(state):
    """Run optimal strategy (backward compat for API)."""
    return run_daily_strategy(state, "optimal")


def run_all_strategies():
    """Run all strategies, return dict of results."""
    vaults = load_live_vaults()
    results = {}

    for sname in ALL_STRATEGY_NAMES:
        state = load_state(sname)
        if state["status"] == "STOPPED":
            equity = mark_to_market(state, vaults)
            results[sname] = {"state": state, "actions": [], "equity": equity}
            continue

        state, actions, equity, _ = run_daily_strategy(state, sname, vaults)
        save_state(state, sname)
        results[sname] = {"state": state, "actions": actions, "equity": equity}

    return results, vaults


# ═══════════════════════════════════════════════════════════════════════
# DISPLAY
# ═══════════════════════════════════════════════════════════════════════

def print_dashboard(state, strategy_name="optimal", actions=None, equity=None, vaults=None):
    ts = now_ts()
    strat = STRATEGIES[strategy_name]
    max_pos = strat["max_pos"]
    hold_days = strat["hold_days"]

    if equity is None:
        vaults = load_live_vaults()
        equity = mark_to_market(state, vaults)

    total_return = (equity - state["initial_capital"]) / state["initial_capital"]
    days_active = len(state["equity_log"])
    peak = max(e["equity"] for e in state["equity_log"]) if state["equity_log"] else equity
    dd = (equity - peak) / peak if peak > 0 else 0

    print(f"\n{'═'*78}")
    print(f"  VAULTVISION PAPER TRADING — {state['status']}")
    print(f"  Strategy: {strat['name']}(hold={hold_days}d, max_pos={max_pos})")
    print(f"  Verdict:  {strat['verdict']}")
    print(f"{'═'*78}")

    print(f"\n  Started     : {state['start_date']}")
    print(f"  Days active : {days_active}")
    print(f"  Total trades: {state['total_trades']}")
    print(f"  Slippage    : ${state['total_slippage']:.2f}")

    print(f"\n  ┌────────────────────────────────────────────┐")
    print(f"  │  Initial Capital : ${state['initial_capital']:>10,.2f}           │")
    print(f"  │  Current Equity  : ${equity:>10,.2f}           │")
    print(f"  │  Cash Available  : ${state['cash']:>10,.2f}           │")
    print(f"  │  Total Return    : {total_return*100:>+9.2f}%            │")
    print(f"  │  Peak Equity     : ${peak:>10,.2f}           │")
    print(f"  │  Current DD      : {dd*100:>+9.2f}%            │")
    print(f"  │  DD Stop Level   : {MAX_DRAWDOWN_STOP*100:>+9.1f}%            │")
    print(f"  └────────────────────────────────────────────┘")

    # Open positions
    print(f"\n  OPEN POSITIONS ({len(state['positions'])}/{max_pos}):")
    if state["positions"]:
        print(f"  {'VAULT':<30} {'ENTRY':>10} {'CURRENT':>10} {'PnL':>9} {'PnL $':>8} {'HELD':>6}")
        print(f"  {'─'*30} {'─'*10} {'─'*10} {'─'*9} {'─'*8} {'─'*6}")
        for pos in state["positions"]:
            pk = pos["vault_pk"]
            if vaults and pk in vaults:
                current = vaults[pk]["current_val"]
                if current and pos["entry_val"] > 0:
                    growth = (current - pos["entry_val"]) / pos["entry_val"]
                    pnl_pct = growth * (1 - LEADER_COMMISSION) if growth > 0 else growth
                else:
                    pnl_pct = 0
            else:
                pnl_pct = 0

            held = (ts - pos["entry_ts"]) / 86400
            pnl_usd = pos['capital'] * pnl_pct
            print(f"  {pos['vault_name'][:30]:<30} ${pos['raw_alloc']:>9,.0f} "
                  f"${pos['capital']*(1+pnl_pct):>9,.0f} {pnl_pct*100:>+8.1f}% {pnl_usd:>+7.0f}$ {held:>5.0f}d")
    else:
        print(f"  (no open positions)")

    # Today's actions
    if actions:
        print(f"\n  TODAY'S ACTIONS:")
        for action_type, name, value, reasons in actions:
            if action_type == "ENTER":
                print(f"    + ENTER {name} (score: {value:.1f})")
                for r in reasons:
                    print(f"      - {r}")
            elif action_type == "EXIT":
                print(f"    - EXIT  {name} (PnL: ${value:+,.2f})")
                for r in reasons:
                    print(f"      - {r}")

    # Recent closed trades
    if state["closed_trades"]:
        recent = state["closed_trades"][-5:]
        print(f"\n  RECENT CLOSED TRADES:")
        print(f"  {'VAULT':<25} {'IN':>8} {'OUT':>8} {'PnL':>9} {'DAYS':>5}")
        print(f"  {'─'*25} {'─'*8} {'─'*8} {'─'*9} {'─'*5}")
        for t in recent:
            print(f"  {t['vault_name'][:25]:<25} ${t['capital_in']:>7,.0f} ${t['capital_out']:>7,.0f} "
                  f"{t['pnl_pct']:>+8.1f}% {t['held_days']:>4.0f}d")

    print()


def print_compare(results, vaults):
    """Print side-by-side comparison table with HLP benchmark."""
    print(f"\n{'═'*100}")
    print(f"  STRATEGY COMPARISON — ALL 6 RUNNING IN PARALLEL ($10K each)")
    print(f"{'═'*100}")
    print(f"  {'STRATEGY':<22} {'EQUITY':>12} {'RETURN':>9} {'DD':>8} {'POS':>5} {'TRADES':>7} {'VERDICT':<18}")
    print(f"  {'─'*22} {'─'*12} {'─'*9} {'─'*8} {'─'*5} {'─'*7} {'─'*18}")

    ranked = []
    for sname in ALL_STRATEGY_NAMES:
        r = results[sname]
        state = r["state"]
        equity = r["equity"]
        ret = (equity - INITIAL_CAPITAL) / INITIAL_CAPITAL
        peak = max(e["equity"] for e in state["equity_log"]) if state["equity_log"] else equity
        dd = (equity - peak) / peak if peak > 0 else 0
        ranked.append((sname, equity, ret, dd, len(state["positions"]), state["total_trades"]))

    ranked.sort(key=lambda x: x[2], reverse=True)

    for i, (sname, equity, ret, dd, n_pos, trades) in enumerate(ranked):
        strat = STRATEGIES[sname]
        medal = "🥇" if i == 0 else "🥈" if i == 1 else "🥉" if i == 2 else "  "
        print(f"  {medal}{strat['name']:<20} ${equity:>10,.2f} {ret*100:>+8.2f}% {dd*100:>+7.2f}% "
              f"{n_pos:>5} {trades:>7} {strat['verdict']:<18}")

    # v2: HLP benchmark
    hlp = get_hlp_benchmark(vaults)
    if hlp:
        # Compute HLP return over the same period as our strategies
        start_ts = None
        for sname in ALL_STRATEGY_NAMES:
            state = results[sname]["state"]
            if state.get("equity_log"):
                sts = state["equity_log"][0].get("ts")
                if sts and (start_ts is None or sts < start_ts):
                    start_ts = sts
        if start_ts:
            hlp_start = get_val(hlp["values"], start_ts, 86400 * 3)
            hlp_end = hlp["current_val"]
            if hlp_start and hlp_start > 0:
                hlp_ret = (hlp_end - hlp_start) / hlp_start
                print(f"\n  {'─'*80}")
                print(f"  📊 BENCHMARK: {hlp['name'][:30]} → {hlp_ret*100:+.2f}% (passive hold)")
                beating = sum(1 for r in ranked if r[2] > hlp_ret)
                print(f"     {beating}/{len(ranked)} strategies beating HLP benchmark")

    # v2: Position overlap warning
    vault_counts = {}
    for sname in ALL_STRATEGY_NAMES:
        state = results[sname]["state"]
        for p in state.get("positions", []):
            vn = p.get("vault_name", "?")
            vault_counts[vn] = vault_counts.get(vn, 0) + 1
    overlap = {v: c for v, c in vault_counts.items() if c >= 3}
    if overlap:
        print(f"\n  ⚠️  OVERLAP WARNING — vaults held by 3+ strategies:")
        for v, c in sorted(overlap.items(), key=lambda x: -x[1]):
            print(f"     {v}: {c} strategies (correlated risk!)")

    print(f"\n  Total virtual capital deployed: ${INITIAL_CAPITAL * len(STRATEGIES):,}")
    print(f"  Note: Each strategy runs independently with its own $10K")
    print()


def print_history(state, strategy_name="optimal"):
    strat = STRATEGIES[strategy_name]
    print(f"\n  EQUITY HISTORY — {strat['name']}")
    print(f"  {'DATE':<12} {'EQUITY':>12} {'RETURN':>9} {'FROM PREV':>10}")
    print(f"  {'─'*12} {'─'*12} {'─'*9} {'─'*10}")
    prev = state["initial_capital"]
    for e in state["equity_log"]:
        total_ret = (e["equity"] - state["initial_capital"]) / state["initial_capital"]
        daily_ret = (e["equity"] - prev) / prev if prev > 0 else 0
        print(f"  {e['date']:<12} ${e['equity']:>11,.2f} {total_ret*100:>+8.2f}% {daily_ret*100:>+9.2f}%")
        prev = e["equity"]

    if state["closed_trades"]:
        wins = sum(1 for t in state["closed_trades"] if t["pnl"] > 0)
        total = len(state["closed_trades"])
        avg_pnl = sum(t["pnl_pct"] for t in state["closed_trades"]) / total if total else 0
        print(f"\n  TRADE STATS:")
        print(f"    Total closed : {total}")
        if total:
            print(f"    Win rate     : {wins}/{total} ({wins/total*100:.0f}%)")
        print(f"    Avg PnL      : {avg_pnl:+.1f}%")
        if total:
            print(f"    Best trade   : {max(t['pnl_pct'] for t in state['closed_trades']):+.1f}%")
            print(f"    Worst trade  : {min(t['pnl_pct'] for t in state['closed_trades']):+.1f}%")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="VaultVision Paper Trading — Multi-Strategy")
    parser.add_argument("--status", action="store_true", help="Show current portfolio(s)")
    parser.add_argument("--reset", action="store_true", help="Reset all portfolios to $10K")
    parser.add_argument("--history", action="store_true", help="Show equity history")
    parser.add_argument("--compare", action="store_true", help="Side-by-side strategy comparison")
    parser.add_argument("--strategy", type=str, default=None,
                        help="Run single strategy (optimal|composite|smart_money|risk_off|eq_gap|tvl_accel)")
    args = parser.parse_args()

    target_strategies = [args.strategy] if args.strategy else ALL_STRATEGY_NAMES

    # Validate strategy name
    if args.strategy and args.strategy not in STRATEGIES:
        print(f"  ERROR: Unknown strategy '{args.strategy}'")
        print(f"  Available: {', '.join(ALL_STRATEGY_NAMES)}")
        return

    if args.reset:
        for sname in target_strategies:
            state = new_state()
            save_state(state, sname)
            print(f"  [{STRATEGIES[sname]['name']}] Reset to ${INITIAL_CAPITAL:,}")
        return

    if args.history:
        for sname in target_strategies:
            state = load_state(sname)
            print_history(state, sname)
        return

    if args.compare:
        results, vaults = run_all_strategies()
        print_compare(results, vaults)
        return

    if args.status:
        vaults = load_live_vaults()
        for sname in target_strategies:
            state = load_state(sname)
            equity = mark_to_market(state, vaults)
            print_dashboard(state, sname, equity=equity, vaults=vaults)
        return

    # ── DAILY RUN ──
    if args.strategy:
        state = load_state(args.strategy)
        if state["status"] == "STOPPED":
            print(f"\n  [{STRATEGIES[args.strategy]['name']}] STOPPED. Use --reset to restart.")
            return
        print(f"\n  Running {STRATEGIES[args.strategy]['name']}...")
        state, actions, equity, vaults = run_daily_strategy(state, args.strategy)
        save_state(state, args.strategy)
        print_dashboard(state, args.strategy, actions, equity, vaults)
    else:
        # Run ALL strategies
        print(f"\n  Running all {len(STRATEGIES)} strategies...")
        results, vaults = run_all_strategies()

        # Print each strategy dashboard briefly
        for sname in ALL_STRATEGY_NAMES:
            r = results[sname]
            state = r["state"]
            equity = r["equity"]
            ret = (equity - INITIAL_CAPITAL) / INITIAL_CAPITAL
            n_act = len(r["actions"])
            strat = STRATEGIES[sname]
            print(f"  [{strat['name']:<22}] Equity: ${equity:>10,.2f}  Return: {ret*100:>+7.2f}%  "
                  f"Pos: {len(state['positions'])}/{strat['max_pos']}  Actions: {n_act}")

        # Full comparison
        print_compare(results, vaults)

        # Show detailed dashboard for best strategy
        best = max(results.items(), key=lambda x: x[1]["equity"])
        best_name = best[0]
        print(f"  Detailed view: best performer ({STRATEGIES[best_name]['name']})")
        print_dashboard(best[1]["state"], best_name, best[1]["actions"], best[1]["equity"], vaults)

    print(f"  Next run: tomorrow (python3 paper_trade.py)")


if __name__ == "__main__":
    main()
