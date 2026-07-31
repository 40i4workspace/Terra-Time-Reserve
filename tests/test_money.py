from decimal import Decimal
import pytest
from app.money import AmountError, SCALE, amount, storage

def test_preserves_72_decimal_places_exactly():
    raw = "1234567890123456789012345678901234567890123456789012345678901234567890.123456789012345678901234567890123456789012345678901234567890123456789012"
    assert storage(raw).endswith("123456789012345678901234567890123456789012345678901234567890123456789012")
    assert amount(raw).as_tuple().exponent == -SCALE

def test_rejects_float_and_precision_loss():
    with pytest.raises(AmountError): amount(0.1)
    with pytest.raises(AmountError): amount("1." + "1" * 73)
