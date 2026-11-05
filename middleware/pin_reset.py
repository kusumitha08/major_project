import hashlib
import hmac
import re
import secrets
import time


OTP_TTL_SECONDS = 5 * 60
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
OTP_MAX_RESENDS = 3


def normalize_mobile(value, default_country_code="+91"):
    mobile = re.sub(r"[\s()-]", "", str(value or ""))
    if re.fullmatch(r"\d{10}", mobile):
        if not re.fullmatch(r"\+\d{1,3}", default_country_code):
            raise ValueError("Default country code must use international format")
        mobile = f"{default_country_code}{mobile}"
    if not re.fullmatch(r"\+[1-9]\d{7,14}", mobile):
        raise ValueError("Enter a valid mobile number")
    return mobile


class PinResetError(Exception):
    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


class PinResetManager:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.challenges = {}
        self.last_sent = {}
        self.failures = {}

    def _purge_expired(self, now):
        self.challenges = {
            flow_id: challenge
            for flow_id, challenge in self.challenges.items()
            if challenge["expires_at"] > now
        }
        self.last_sent = {
            mobile: sent_at
            for mobile, sent_at in self.last_sent.items()
            if now - sent_at < OTP_TTL_SECONDS
        }
        self.failures = {
            mobile: state
            for mobile, state in self.failures.items()
            if now - state["started_at"] < OTP_TTL_SECONDS
        }

    @staticmethod
    def _otp_digest(salt, otp):
        return hashlib.sha256(salt + otp.encode("ascii")).digest()

    def _new_otp(self):
        return f"{secrets.randbelow(1_000_000):06d}"

    def start(self, aadhaar_id, recipient):
        now = self.clock()
        self._purge_expired(now)
        previous_send = self.last_sent.get(recipient)
        if previous_send is not None:
            wait = OTP_RESEND_COOLDOWN_SECONDS - (now - previous_send)
            if wait > 0:
                raise PinResetError("Please wait before requesting another OTP", 429)

        flow_id = secrets.token_urlsafe(32)
        otp = self._new_otp() if aadhaar_id else None
        salt = secrets.token_bytes(16)
        digest_otp = otp or self._new_otp()
        self.challenges[flow_id] = {
            "aadhaar_id": aadhaar_id,
            "recipient": recipient,
            "salt": salt,
            "otp_hash": self._otp_digest(salt, digest_otp),
            "expires_at": now + OTP_TTL_SECONDS,
            "sent_at": now,
            "verified": False,
            "resends": 0,
        }
        self.last_sent[recipient] = now
        return flow_id, otp

    def resend(self, flow_id):
        now = self.clock()
        self._purge_expired(now)
        challenge = self.challenges.get(flow_id)
        if not challenge:
            raise PinResetError("This reset request has expired. Start again.", 400)
        if not challenge["aadhaar_id"]:
            return None
        if challenge["verified"]:
            raise PinResetError("OTP has already been verified", 400)
        if challenge["resends"] >= OTP_MAX_RESENDS:
            raise PinResetError("OTP resend limit reached. Start again later.", 429)
        previous_send = self.last_sent.get(challenge["recipient"], now)
        wait = OTP_RESEND_COOLDOWN_SECONDS - (now - previous_send)
        if wait > 0:
            raise PinResetError("Please wait before requesting another OTP", 429)

        otp = self._new_otp()
        challenge["salt"] = secrets.token_bytes(16)
        challenge["otp_hash"] = self._otp_digest(challenge["salt"], otp)
        challenge["resends"] += 1
        challenge["expires_at"] = now + OTP_TTL_SECONDS
        challenge["sent_at"] = now
        self.last_sent[challenge["recipient"]] = now
        return otp

    def verify(self, flow_id, otp):
        now = self.clock()
        self._purge_expired(now)
        challenge = self.challenges.get(flow_id)
        if not challenge:
            raise PinResetError("The OTP is invalid or expired", 400)
        failure = self.failures.get(challenge["recipient"])
        if failure and failure["attempts"] >= OTP_MAX_ATTEMPTS:
            raise PinResetError("Too many incorrect OTP attempts. Start again later.", 429)
        if not challenge["aadhaar_id"] or challenge["verified"]:
            self._record_failure(challenge["recipient"], now)
            raise PinResetError("The OTP is invalid or expired", 400)

        otp = str(otp)
        if not re.fullmatch(r"[0-9]{6}", otp):
            self._record_failure(challenge["recipient"], now)
            raise PinResetError("The OTP is invalid or expired", 400)
        supplied = self._otp_digest(challenge["salt"], otp)
        if not hmac.compare_digest(supplied, challenge["otp_hash"]):
            self._record_failure(challenge["recipient"], now)
            raise PinResetError("The OTP is invalid or expired", 400)

        challenge["verified"] = True
        self.failures.pop(challenge["recipient"], None)
        return True

    def _record_failure(self, mobile, now):
        failure = self.failures.get(mobile)
        if not failure or now - failure["started_at"] >= OTP_TTL_SECONDS:
            failure = {"attempts": 0, "started_at": now}
            self.failures[mobile] = failure
        failure["attempts"] += 1

    def consume_verified(self, flow_id):
        now = self.clock()
        self._purge_expired(now)
        challenge = self.challenges.get(flow_id)
        if not challenge or not challenge["verified"] or not challenge["aadhaar_id"]:
            raise PinResetError("Verify the OTP before resetting your PIN", 400)
        self.challenges.pop(flow_id, None)
        return challenge["aadhaar_id"]