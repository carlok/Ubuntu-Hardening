from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from availability.poll import (
    Availability,
    PollerError,
    build_message,
    check_availability,
    parse_server_types,
    parse_csv,
    run,
)


def server_type(name, location="fsn1", available=False):
    return SimpleNamespace(
        name=name,
        locations=[SimpleNamespace(location=SimpleNamespace(name=location), available=available)],
        prices=[
            {
                "location": location,
                "price_hourly": "0.01",
                "price_monthly": "4.50",
            }
        ],
    )


def client_for(*types):
    return SimpleNamespace(server_types=SimpleNamespace(get_all=lambda: list(types)))


def smtp_env(**overrides):
    env = {
        "HCLOUD_TOKEN": "secret-token",
        "POLL_SERVER_TYPES": "cx22,cx23,cx33",
        "POLL_LOCATION": "fsn1",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "587",
        "SMTP_USER": "mailer",
        "SMTP_PASS": "secret-password",
        "SMTP_FROM": "from@example.com",
        "ALERT_EMAIL": "to@example.com",
    }
    env.update(overrides)
    return env


def test_parse_server_types_trims_deduplicates_and_ignores_empty_items():
    assert parse_server_types(" cx22, ,cx23,cx22, cx33 ") == ["cx22", "cx23", "cx33"]


def test_parse_locations_accepts_multiple_values():
    assert parse_csv(" fsn1, nbg1,fsn1 ") == ["fsn1", "nbg1"]


def test_check_availability_returns_per_type_location_status():
    results = check_availability(
        client_for(server_type("cx22", available=True), server_type("cx23")),
        ["cx22", "cx23"],
        "fsn1",
    )
    assert [item.available for item in results] == [True, False]
    assert results[0].price_hourly == "0.01"


def test_check_availability_checks_multiple_locations():
    client = client_for(
        SimpleNamespace(
            name="cx22",
            locations=[
                SimpleNamespace(location=SimpleNamespace(name="fsn1"), available=True),
                SimpleNamespace(location=SimpleNamespace(name="nbg1"), available=False),
            ],
            prices=[
                {"location": "fsn1", "price_hourly": "0.01", "price_monthly": "4.50"},
                {"location": "nbg1", "price_hourly": "0.02", "price_monthly": "5.00"},
            ],
        )
    )
    results = check_availability(client, ["cx22"], ["fsn1", "nbg1"])
    assert [(item.location, item.available) for item in results] == [("fsn1", True), ("nbg1", False)]


def test_unknown_type_is_an_error():
    with pytest.raises(PollerError, match="Unknown Hetzner server type"):
        check_availability(client_for(server_type("cx22")), ["cx99"], "fsn1")


def test_unsupported_location_is_an_error():
    with pytest.raises(PollerError, match="not supported"):
        check_availability(client_for(server_type("cx22")), ["cx22"], "nbg1")


def test_no_email_when_all_types_are_unavailable():
    smtp = MagicMock()
    assert run(smtp_env(), lambda **_: client_for(server_type("cx22"), server_type("cx23"), server_type("cx33")), smtp_factory=smtp) == 0
    smtp.assert_not_called()


def test_one_email_contains_all_available_types():
    smtp = MagicMock()
    connection = smtp.return_value.__enter__.return_value
    env = smtp_env()
    result = run(
        env,
        lambda **_: client_for(
            server_type("cx22", available=True),
            server_type("cx23", available=True),
            server_type("cx33"),
        ),
        smtp_factory=smtp,
    )
    assert result == 0
    sent = connection.send_message.call_args.args[0]
    body = sent.get_content()
    assert "cx22" in body and "cx23" in body and "cx33" not in body
    assert "0.01" in body and "4.50" in body


def test_smtp_failure_returns_nonzero_without_exposing_credentials(capsys):
    smtp = MagicMock()
    smtp.return_value.__enter__.side_effect = ConnectionError("secret-password")
    assert run(smtp_env(), lambda **_: client_for(server_type("cx22", available=True)), smtp_factory=smtp) == 1
    output = capsys.readouterr()
    assert "secret-token" not in output.out + output.err
    assert "secret-password" not in output.out + output.err


def test_api_failure_returns_nonzero(capsys):
    def failing_client(**_):
        return SimpleNamespace(
            server_types=SimpleNamespace(get_all=MagicMock(side_effect=ConnectionError("offline")))
        )

    assert run(smtp_env(), failing_client) == 1
    assert "Availability poll failed" in capsys.readouterr().err


def test_message_has_expected_sender_and_recipient():
    message = build_message(
        [Availability("cx22", "fsn1", True, "0.01", "4.50")],
        "from@example.com",
        "to@example.com",
    )
    assert message["From"] == "from@example.com"
    assert message["To"] == "to@example.com"
