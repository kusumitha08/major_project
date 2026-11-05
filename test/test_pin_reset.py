import pytest

from middleware.pin_reset import PinResetError, PinResetManager, normalize_mobile


def test_mobile_numbers_are_normalized_for_lookup():
    assert normalize_mobile("98765 43210") == "+919876543210"
    assert normalize_mobile("+1 (202) 555-0123") == "+12025550123"


def test_mobile_number_rejects_invalid_values():
    with pytest.raises(ValueError):
        normalize_mobile("12345")


def test_otp_expires_after_five_minutes():
    now = [100.0]
    manager = PinResetManager(clock=lambda: now[0])
    flow_id, otp = manager.start("aadhaar-id", "+919876543210")
    now[0] += 301
    with pytest.raises(PinResetError, match="invalid or expired"):
        manager.verify(flow_id, otp)


def test_resent_otp_gets_a_fresh_five_minute_lifetime():
    now = [100.0]
    manager = PinResetManager(clock=lambda: now[0])
    flow_id, _ = manager.start("aadhaar-id", "+919876543210")
    now[0] += 60
    resent_otp = manager.resend(flow_id)
    now[0] += 299
    assert manager.verify(flow_id, resent_otp)


def test_otp_limits_incorrect_attempts_across_new_flows():
    now = [100.0]
    manager = PinResetManager(clock=lambda: now[0])
    flow_id, otp = manager.start("aadhaar-id", "+919876543210")
    wrong_otp = f"{(int(otp) + 1) % 1_000_000:06d}"
    for _ in range(5):
        with pytest.raises(PinResetError, match="invalid or expired"):
            manager.verify(flow_id, wrong_otp)
    with pytest.raises(PinResetError, match="Too many"):
        manager.verify(flow_id, wrong_otp)


def test_resend_requires_cooldown_and_has_a_limit():
    now = [100.0]
    manager = PinResetManager(clock=lambda: now[0])
    flow_id, _ = manager.start("aadhaar-id", "+919876543210")
    with pytest.raises(PinResetError, match="wait"):
        manager.resend(flow_id)

    for _ in range(3):
        now[0] += 60
        manager.resend(flow_id)
    now[0] += 60
    with pytest.raises(PinResetError, match="limit"):
        manager.resend(flow_id)


def test_verified_reset_flow_is_one_time():
    manager = PinResetManager()
    flow_id, otp = manager.start("aadhaar-id", "+919876543210")
    manager.verify(flow_id, otp)
    assert manager.consume_verified(flow_id) == "aadhaar-id"
    with pytest.raises(PinResetError, match="Verify the OTP"):
        manager.consume_verified(flow_id)