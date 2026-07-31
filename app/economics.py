"""Pure, deterministic RBH economics. All inputs and outputs are Decimal, never float."""
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal, ROUND_DOWN, localcontext
from enum import StrEnum
from .money import CONTEXT, amount, calculated_amount, calculated_signed_amount

ZERO = Decimal("0")
HUNDRED = Decimal("100")
DEFAULT_RBH_USD = Decimal("30")
PEG_BAND = Decimal("0.20")
ANNUAL_PENSION_RATE = Decimal("0.08")
MONTHLY_PENSION_RATE = ANNUAL_PENSION_RATE / Decimal("12")

class AssetCode(StrEnum):
    GOLD = "GOLD"; OIL = "OIL"; SILVER = "SILVER"; NATGAS = "NATGAS"
    BITCOIN = "BTC"; USD = "USD"; JPY = "JPY"; PLATINUM = "PLATINUM"
    SP500 = "SP500"; APPLE = "APPLE"

@dataclass(frozen=True)
class TimeQuote:
    asset: AssetCode
    source_price_usd: Decimal
    effective_rbh_usd: Decimal
    trr_per_unit: Decimal
    peg_lower_usd: Decimal
    peg_upper_usd: Decimal

def clamp_rbh(observed_rbh_usd: Decimal | str, baseline_rbh_usd: Decimal | str = DEFAULT_RBH_USD) -> tuple[Decimal, Decimal, Decimal]:
    """Apply the ±20% peg guard to an oracle-supplied RBH value."""
    observed, baseline = amount(observed_rbh_usd), amount(baseline_rbh_usd)
    if baseline == ZERO: raise ValueError("RBH baseline must be positive")
    lower, upper = baseline * (Decimal("1") - PEG_BAND), baseline * (Decimal("1") + PEG_BAND)
    return max(lower, min(observed, upper)), lower, upper

def quote_in_time(asset: AssetCode, source_price_usd: Decimal | str, observed_rbh_usd: Decimal | str,
                  baseline_rbh_usd: Decimal | str = DEFAULT_RBH_USD) -> TimeQuote:
    price = amount(source_price_usd)
    effective, lower, upper = clamp_rbh(observed_rbh_usd, baseline_rbh_usd)
    if price == ZERO: raise ValueError("asset price must be positive")
    with localcontext(CONTEXT):
        trr_per_unit = calculated_amount(price / effective)
    return TimeQuote(asset, price, effective, trr_per_unit, amount(lower), amount(upper))

STAKE_PLANS = {30: (Decimal("1"), Decimal("0.01")), 90: (Decimal("2"), Decimal("0.03")),
               180: (Decimal("4"), Decimal("0.07")), 365: (Decimal("4"), Decimal("0.15"))}
def stake_terms(days: int, principal_trr: Decimal | str) -> dict:
    if days not in STAKE_PLANS: raise ValueError("term must be 30, 90, 180, or 365 days")
    principal = amount(principal_trr)
    if principal == ZERO: raise ValueError("stake must be positive")
    multiplier, rate = STAKE_PLANS[days]
    return {"principal_trr": principal, "term_days": days, "power_multiplier": multiplier,
            "reward_trr": amount(principal * rate), "maturity_date": date.today() + timedelta(days=days)}

def leverage_terms(margin_trr: Decimal | str, leverage: int, entry_trr_per_unit: Decimal | str, side: str) -> dict:
    margin, entry = amount(margin_trr), amount(entry_trr_per_unit)
    if leverage not in {1, 2, 5, 10, 20}: raise ValueError("leverage must be 1, 2, 5, 10, or 20")
    if margin == ZERO or entry == ZERO or side not in {"LONG", "SHORT"}: raise ValueError("invalid position terms")
    with localcontext(CONTEXT):
        notional = calculated_amount(margin * leverage)
        units = calculated_amount(notional / entry)
        liquidation = calculated_amount(entry * (Decimal("1") - Decimal("0.8") / leverage if side == "LONG" else Decimal("1") + Decimal("0.8") / leverage))
    return {"margin_trr": margin, "leverage": leverage, "notional_trr": notional,
            "units": units, "liquidation_price_trr": liquidation}

def settle_leverage(margin_trr: Decimal | str, leverage: int, entry: Decimal | str, exit: Decimal | str, side: str) -> dict:
    terms = leverage_terms(margin_trr, leverage, entry, side)
    exit_price = amount(exit)
    movement = (exit_price - amount(entry)) / amount(entry)
    if side == "SHORT": movement = -movement
    pnl = calculated_signed_amount(terms["notional_trr"] * movement)
    equity = max(ZERO, calculated_amount(terms["margin_trr"] + pnl))
    return {**terms, "exit_trr_per_unit": exit_price, "pnl_trr": pnl, "settled_equity_trr": equity,
            "liquidated": equity == ZERO}

def pension_contribution(monthly_earnings_trr: Decimal | str, rate_percent: int) -> dict:
    earnings = amount(monthly_earnings_trr)
    if rate_percent not in {3, 5, 10}: raise ValueError("contribution rate must be 3, 5, or 10 percent")
    contribution = calculated_amount(earnings * Decimal(rate_percent) / HUNDRED)
    cash = calculated_amount(contribution * Decimal("0.10"))
    capital = calculated_amount(contribution - cash)
    return {"monthly_earnings_trr": earnings, "contribution_trr": contribution,
            "immediate_payout_trr": cash, "capitalized_trr": capital}

def capital_value(principal_trr: Decimal | str, months: int, annual_rate: Decimal | str = ANNUAL_PENSION_RATE) -> Decimal:
    if months < 0: raise ValueError("months must be non-negative")
    principal, annual = amount(principal_trr), amount(annual_rate)
    with localcontext(CONTEXT):
        return calculated_amount(principal * ((Decimal("1") + annual / Decimal("12")) ** months))
