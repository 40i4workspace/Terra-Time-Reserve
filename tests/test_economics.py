from decimal import Decimal
import pytest
from app.economics import (AssetCode, capital_value, clamp_rbh, leverage_terms, pension_contribution,
                           quote_in_time, settle_leverage, stake_terms)

def test_rbh_peg_clamps_to_twenty_percent_band():
    effective, low, high = clamp_rbh("100", "30")
    assert (effective, low, high) == (Decimal("36"), Decimal("24"), Decimal("36"))
    assert quote_in_time(AssetCode.GOLD, "3600", "100").trr_per_unit == Decimal("100")

def test_staking_and_leverage_are_time_denominated():
    terms = stake_terms(90, "100")
    assert terms["power_multiplier"] == Decimal("2")
    assert terms["reward_trr"] == Decimal("3")
    opened = leverage_terms("10", 5, "2", "LONG")
    assert opened["notional_trr"] == Decimal("50")
    assert opened["units"] == Decimal("25")
    assert settle_leverage("10", 5, "2", "2.4", "LONG")["pnl_trr"] == Decimal("10")

def test_pension_split_and_compounding():
    month = pension_contribution("1000", 5)
    assert month["contribution_trr"] == Decimal("50")
    assert month["immediate_payout_trr"] == Decimal("5")
    assert month["capitalized_trr"] == Decimal("45")
    assert capital_value("90", 12) > Decimal("97")
    with pytest.raises(ValueError): pension_contribution("100", 4)
