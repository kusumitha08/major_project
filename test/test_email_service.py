from middleware.email_service import is_configured, send_email


def test_email_configuration_requires_smtp_credentials(monkeypatch):
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    assert not is_configured()

    monkeypatch.setenv("SMTP_USERNAME", "sender@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")
    assert is_configured()


def test_send_email_uses_authenticated_starttls(monkeypatch):
    monkeypatch.setenv("SMTP_USERNAME", "sender@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")
    sent_messages = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            assert host == "smtp.gmail.com"
            assert port == 587
            assert timeout == 10

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def ehlo(self):
            pass

        def starttls(self, context):
            assert context is not None

        def login(self, username, password):
            assert username == "sender@example.com"
            assert password == "app-password"

        def send_message(self, message):
            sent_messages.append(message)

    monkeypatch.setattr("middleware.email_service.smtplib.SMTP", FakeSMTP)
    send_email("applicant@example.com", "PIN reset", "Your OTP is 123456")

    assert len(sent_messages) == 1
    assert sent_messages[0]["To"] == "applicant@example.com"
    assert sent_messages[0]["Subject"] == "PIN reset"
    assert sent_messages[0].get_content().strip() == "Your OTP is 123456"