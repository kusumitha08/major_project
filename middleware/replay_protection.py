import hashlib
import secrets
import time


VERIFICATION_DOMAIN = "cross-blockchain-identity-verification-v1"
NONCE_TTL_SECONDS = 300


def build_verification_message(identity_hash, nonce, request_id):
    return "|".join((VERIFICATION_DOMAIN, request_id, nonce, identity_hash))


class ReplayProtection:
    def __init__(self, ttl_seconds=NONCE_TTL_SECONDS, clock=None):
        self.ttl_seconds = ttl_seconds
        self.clock = clock or time.time
        self._pending = {}

    def issue(self, identity_hash):
        request_id = secrets.token_urlsafe(24)
        nonce = secrets.token_hex(32)
        self._pending[request_id] = {
            "identity_hash": identity_hash,
            "nonce": nonce,
            "expires_at": self.clock() + self.ttl_seconds,
        }
        return request_id, nonce, self._pending[request_id]["expires_at"]

    def consume(self, identity_hash, nonce, request_id):
        challenge = self._pending.pop(request_id, None)
        if not challenge:
            return False, "Unknown or already consumed verification request"
        if self.clock() > challenge["expires_at"]:
            return False, "Verification request has expired"
        if not secrets.compare_digest(challenge["nonce"], nonce):
            return False, "Verification nonce does not match the current request"
        if not secrets.compare_digest(challenge["identity_hash"], identity_hash):
            return False, "Verification identity hash does not match the current request"
        return True, None


def hash_verification_message(identity_hash, nonce, request_id):
    message = build_verification_message(identity_hash, nonce, request_id)
    return hashlib.sha256(message.encode("utf-8")).hexdigest()