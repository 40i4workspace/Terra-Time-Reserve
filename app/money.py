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

def signed_amount(value: str | Decimal) -> Decimal:
    """Parse a signed fixed-scale decimal; suitable for P&L, never balances."""
    if isinstance(value, float):
        raise AmountError("binary float amounts are forbidden")
    try:
        with localcontext(CONTEXT):
            parsed = Decimal(value)
            if not parsed.is_finite(): raise AmountError("amount must be finite")
            result = parsed.quantize(QUANTUM, rounding=ROUND_DOWN)
            if parsed != result: raise AmountError("amount has more than 72 fractional digits")
            if len(result.as_tuple().digits) > MAX_PRECISION: raise AmountError("amount exceeds NUMERIC(150,72)")
            return result
    except (InvalidOperation, ValueError) as exc:
        if isinstance(exc, AmountError): raise
        raise AmountError("invalid decimal amount") from exc

def signed_storage(value: str | Decimal) -> str:
    return format(signed_amount(value), f".{SCALE}f")

def calculated_amount(value: Decimal) -> Decimal:
    """Round an internally calculated non-negative value down to the storage scale."""
    if not value.is_finite() or value < 0:
        raise AmountError("calculated amount must be finite and non-negative")
    with localcontext(CONTEXT):
        result = value.quantize(QUANTUM, rounding=ROUND_DOWN)
        if len(result.as_tuple().digits) > MAX_PRECISION:
            raise AmountError("amount exceeds NUMERIC(150,72)")
        return result

def calculated_signed_amount(value: Decimal) -> Decimal:
    if not value.is_finite(): raise AmountError("calculated amount must be finite")
    with localcontext(CONTEXT):
        result = value.quantize(QUANTUM, rounding=ROUND_DOWN)
        if len(result.as_tuple().digits) > MAX_PRECISION: raise AmountError("amount exceeds NUMERIC(150,72)")
        return result
