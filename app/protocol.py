"""Deterministic, simulation-only protocol calculations for Oxygenus.

These routines never mint an externally transferable asset.  They update only the
internal scenario ledger after an ADMIN_ROOT-authorized cycle is recorded.
"""
import hashlib
import hmac
from dataclasses import dataclass
from decimal import Decimal, localcontext
from .money import CONTEXT, calculated_amount, amount

TOTAL_SUPPLY_CAP = Decimal(10) ** 72
PEG_BAND = Decimal("0.20")
MIN_ACTION_RATE = Decimal("0.0001")
MAX_ACTION_RATE = Decimal("0.001")

@dataclass(frozen=True)
class CdcoAction:
    direction: str
    amount: Decimal
    deviation: Decimal
    entropy_commitment: str

def cdco_action(*, observed_rbh: Decimal | str, target_rbh: Decimal | str,
                circulating_supply: Decimal | str, cycle_id: str, secret: str) -> CdcoAction | None:
    """Derive a bounded action after the peg boundary is crossed.

    The HMAC commitment makes the pseudo-random volume reproducible for auditors
    who hold the cycle secret, while avoiding a manipulable public RNG.
    """
    observed, target, supply = amount(observed_rbh), amount(target_rbh), amount(circulating_supply)
    if target <= 0: raise ValueError("target RBH must be positive")
    with localcontext(CONTEXT):
        deviation = (observed - target) / target
        if -PEG_BAND < deviation < PEG_BAND: return None
        digest = hmac.new(secret.encode(), f"CDCO:{cycle_id}".encode(), hashlib.sha512).digest()
        fraction = Decimal(int.from_bytes(digest[:16], "big")) / Decimal(2**128 - 1)
        rate = MIN_ACTION_RATE + (MAX_ACTION_RATE - MIN_ACTION_RATE) * fraction
        desired = calculated_amount(supply * rate)
        direction = "MINT" if deviation >= PEG_BAND else "BURN"
        action = min(desired, TOTAL_SUPPLY_CAP - supply) if direction == "MINT" else min(desired, supply)
        return CdcoAction(direction, calculated_amount(action), calculated_amount(abs(deviation)), digest.hex())

def smart_split(amount_value: Decimal | str) -> tuple[Decimal, Decimal]:
    """Return immutable 1% infrastructure and 99% GSC allocations."""
    value = amount(amount_value)
    if value <= 0: raise ValueError("split amount must be positive")
    with localcontext(CONTEXT):
        operations = calculated_amount(value * Decimal("0.01"))
        return operations, calculated_amount(value - operations)
