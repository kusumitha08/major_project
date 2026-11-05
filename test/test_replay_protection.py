from ecdsa import SigningKey, SECP256k1

from crypto_core.crypto_utils import sign_verification_message, verify_verification_signature
from middleware.replay_protection import ReplayProtection


def make_challenge(protection, identity_hash="identity-hash"):
    request_id, nonce, _ = protection.issue(identity_hash)
    private_key = SigningKey.generate(curve=SECP256k1)
    signature = sign_verification_message(private_key, identity_hash, nonce, request_id)
    return protection, identity_hash, nonce, request_id, signature, private_key.get_verifying_key()


def test_valid_nonce_and_signature_succeed():
    protection, identity_hash, nonce, request_id, signature, public_key = make_challenge(ReplayProtection())
    assert verify_verification_signature(public_key, identity_hash, nonce, request_id, signature)
    assert protection.consume(identity_hash, nonce, request_id) == (True, None)


def test_wrong_nonce_fails():
    protection, identity_hash, _, request_id, _, _ = make_challenge(ReplayProtection())
    valid, error = protection.consume(identity_hash, "wrong-nonce", request_id)
    assert not valid
    assert "nonce" in error.lower()


def test_reused_nonce_fails():
    protection, identity_hash, nonce, request_id, _, _ = make_challenge(ReplayProtection())
    assert protection.consume(identity_hash, nonce, request_id)[0]
    assert not protection.consume(identity_hash, nonce, request_id)[0]


def test_expired_nonce_fails():
    now = [100.0]
    protection, identity_hash, nonce, request_id, _, _ = make_challenge(
        ReplayProtection(ttl_seconds=5, clock=lambda: now[0])
    )
    now[0] = 106.0
    valid, error = protection.consume(identity_hash, nonce, request_id)
    assert not valid
    assert "expired" in error.lower()


def test_invalid_signature_fails():
    _, identity_hash, nonce, request_id, _, public_key = make_challenge(ReplayProtection())
    assert not verify_verification_signature(public_key, identity_hash, nonce, request_id, "00")


def test_modified_identity_hash_fails():
    protection, _, nonce, request_id, _, _ = make_challenge(ReplayProtection())
    valid, error = protection.consume("modified-identity-hash", nonce, request_id)
    assert not valid
    assert "identity hash" in error.lower()


def test_signature_cannot_be_reused_for_another_request():
    protection = ReplayProtection()
    _, identity_hash, _, _, _, _ = make_challenge(protection)
    request_id, nonce, _ = protection.issue(identity_hash)
    private_key = SigningKey.generate(curve=SECP256k1)
    signature = sign_verification_message(private_key, identity_hash, nonce, request_id)
    other_request_id, other_nonce, _ = protection.issue(identity_hash)
    assert not verify_verification_signature(
        private_key.get_verifying_key(), identity_hash, other_nonce, other_request_id, signature
    )