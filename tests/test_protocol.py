from decimal import Decimal
from app.protocol import TOTAL_SUPPLY_CAP, cdco_action, smart_split

def test_cdco_only_acts_at_boundary_and_is_reproducible():
    assert cdco_action(observed_rbh="1.19",target_rbh="1",circulating_supply="1000",cycle_id="cycle-0001",secret="x"*32) is None
    first=cdco_action(observed_rbh="1.2",target_rbh="1",circulating_supply="1000",cycle_id="cycle-0001",secret="x"*32)
    again=cdco_action(observed_rbh="1.2",target_rbh="1",circulating_supply="1000",cycle_id="cycle-0001",secret="x"*32)
    assert first.direction == "MINT" and first.amount == again.amount
    assert cdco_action(observed_rbh=".8",target_rbh="1",circulating_supply="1000",cycle_id="cycle-0002",secret="x"*32).direction == "BURN"

def test_smart_split_conserves_every_unit():
    ops,gsc=smart_split("123.456")
    assert ops == Decimal("1.23456")
    assert ops + gsc == Decimal("123.456")
    assert TOTAL_SUPPLY_CAP == Decimal(10) ** 72
