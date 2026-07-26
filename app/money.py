"""Exact fixed-point quantities used by the vault.

All persisted quantities have exactly 72 decimal places.  Floats are rejected:
using a binary float for a financial amount would silently alter ownership.
"""
from decimal import Decimal, Context, InvalidOperation, ROUND_DOWN, localcontext

SCALE = 72
MAX_PRECISION = 150
QUANTUM = Decimal(1).scaleb(-SCALE)
CONTEXT = Context(prec=MAX_PRECISION, rounding=ROUND_DOWN)

class AmountError(ValueError):
    pass

def amount(value: str | Decimal) -> Decimal:
    """Parse and canonically quantize a non-negative decimal at scale 10^-72."""
    if isinstance(value, float):
        raise AmountError("binary float amounts are forbidden")
    try:
        with localcontext(CONTEXT):
            parsed = Decimal(value)
            if not parsed.is_finite() or parsed < 0:
                raise AmountError("amount must be a finite non-negative decimal")
            result = parsed.quantize(QUANTUM, rounding=ROUND_DOWN)
            # Do not allow callers to make a tiny amount disappear by truncation.
            if parsed != result:
                raise AmountError("amount has more than 72 fractional digits")
            if len(result.as_tuple().digits) > MAX_PRECISION:
                raise AmountError("amount exceeds NUMERIC(150,72)")
            return result
    except (InvalidOperation, ValueError) as exc:
        if isinstance(exc, AmountError):
            raise
        raise AmountError("invalid decimal amount") from exc

def storage(value: str | Decimal) -> str:
    """PostgreSQL-safe fixed-scale wire representation."""
    return format(amount(value), f".{SCALE}f")
