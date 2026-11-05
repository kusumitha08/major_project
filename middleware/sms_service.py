import base64
import os
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def is_configured():
    return all(
        os.getenv(name)
        for name in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER")
    )


def send_sms(to_number, message):
    account_sid = os.environ["TWILIO_ACCOUNT_SID"]
    auth_token = os.environ["TWILIO_AUTH_TOKEN"]
    from_number = os.environ["TWILIO_FROM_NUMBER"]
    endpoint = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    credentials = base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("ascii")
    request = Request(
        endpoint,
        data=urlencode({"To": to_number, "From": from_number, "Body": message}).encode("utf-8"),
        headers={"Authorization": f"Basic {credentials}"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError("SMS provider rejected the message")