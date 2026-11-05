import os
import smtplib
import ssl
from email.message import EmailMessage


def is_configured():
    return bool(os.getenv("SMTP_USERNAME") and os.getenv("SMTP_PASSWORD"))


def send_email(to_address, subject, body):
    username = os.environ["SMTP_USERNAME"]
    message = EmailMessage()
    message["From"] = os.getenv("SMTP_FROM_EMAIL", username)
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(
        os.getenv("SMTP_HOST", "smtp.gmail.com"),
        int(os.getenv("SMTP_PORT", "587")),
        timeout=10,
    ) as server:
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        server.login(username, os.environ["SMTP_PASSWORD"])
        server.send_message(message)