#!/usr/bin/env python3
"""Email when configured Hetzner Cloud server types are available."""

from __future__ import annotations

import os
import smtplib
import sys
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Callable, Mapping

from dotenv import load_dotenv
from hcloud import Client


DEFAULT_LOCATION = "fsn1"


class PollerError(RuntimeError):
    """A configuration, API, or notification error safe to show to operators."""


@dataclass(frozen=True)
class Availability:
    server_type: str
    location: str
    available: bool
    price_hourly: str | None
    price_monthly: str | None


def load_environment() -> None:
    """Load the container-mounted .env or the current directory's .env."""
    env_path = Path("/app/.env")
    if env_path.is_file():
        load_dotenv(env_path, override=True)
    else:
        load_dotenv(override=True)


def parse_csv(value: str) -> list[str]:
    """Return unique, trimmed values in input order."""
    result: list[str] = []
    for item in value.split(","):
        name = item.strip()
        if name and name not in result:
            result.append(name)
    return result


parse_server_types = parse_csv


def _attr(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _location_name(value: Any) -> str | None:
    location = _attr(value, "location")
    return _attr(location, "name", location) if location is not None else None


def _price_for_location(server_type: Any, location: str) -> tuple[str | None, str | None]:
    prices = _attr(server_type, "prices", []) or []
    for price in prices:
        if _attr(price, "location") == location:
            return _attr(price, "price_hourly"), _attr(price, "price_monthly")
    return None, None


def check_availability(
    client: Any, server_type_names: list[str], locations: str | list[str]
) -> list[Availability]:
    """Check configured server types against Hetzner's per-location indicator."""
    if not server_type_names:
        raise PollerError("POLL_SERVER_TYPES must contain at least one server type.")
    location_names = [locations] if isinstance(locations, str) else locations
    location_names = [location.strip() for location in location_names if location.strip()]
    if not location_names:
        raise PollerError("POLL_LOCATION must contain at least one location.")

    try:
        server_types = client.server_types.get_all()
    except Exception as exc:  # SDK exceptions vary by transport/version.
        raise PollerError(f"Hetzner API request failed: {type(exc).__name__}") from exc

    by_name = {_attr(item, "name"): item for item in server_types}
    missing = [name for name in server_type_names if name not in by_name]
    if missing:
        raise PollerError("Unknown Hetzner server type(s): " + ", ".join(missing))

    results: list[Availability] = []
    for location in location_names:
        for name in server_type_names:
            server_type = by_name[name]
            supported_locations = _attr(server_type, "locations", None)
            location_entry = next(
                (entry for entry in (supported_locations or []) if _location_name(entry) == location),
                None,
            )
            if location_entry is None:
                raise PollerError(f"Location {location!r} is not supported for server type {name}.")
            hourly, monthly = _price_for_location(server_type, location)
            results.append(
                Availability(
                    server_type=name,
                    location=location,
                    available=bool(_attr(location_entry, "available", False)),
                    price_hourly=hourly,
                    price_monthly=monthly,
                )
            )
    return results


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise PollerError(f"{name} must be set.")
    return value


def _format_price(value: str | None, currency: str = "") -> str:
    return f"{value} {currency}".strip() if value is not None else "unknown"


def build_message(
    matches: list[Availability], sender: str, recipient: str
) -> EmailMessage:
    locations = list(dict.fromkeys(item.location for item in matches))
    location_label = ", ".join(locations)
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = f"Hetzner capacity reported available in {location_label}"
    lines = [
        "Hetzner Cloud currently reports the following configured server types "
        f"as available in {location_label}:",
        "",
    ]
    for item in matches:
        lines.append(
            f"- {item.server_type}: reported available; "
            f"hourly={_format_price(item.price_hourly)}, "
            f"monthly={_format_price(item.price_monthly)}"
        )
    lines.extend(
        [
            "",
            "Availability is an indicator only and does not guarantee that a "
            "server creation request will succeed.",
        ]
    )
    message.set_content("\n".join(lines))
    return message


def send_email(
    message: EmailMessage,
    env: Mapping[str, str],
    smtp_factory: Callable[..., Any] = smtplib.SMTP,
) -> None:
    host = _required(env, "SMTP_HOST")
    sender = _required(env, "SMTP_FROM")
    _required(env, "ALERT_EMAIL")
    try:
        port = int(env.get("SMTP_PORT", "587"))
    except ValueError as exc:
        raise PollerError("SMTP_PORT must be an integer.") from exc
    if not 1 <= port <= 65535:
        raise PollerError("SMTP_PORT must be between 1 and 65535.")

    try:
        with smtp_factory(host, port, timeout=30) as smtp:
            smtp.starttls()
            username = env.get("SMTP_USER", "").strip()
            password = env.get("SMTP_PASS", "")
            if username or password:
                if not username or not password:
                    raise PollerError("SMTP_USER and SMTP_PASS must be set together.")
                smtp.login(username, password)
            smtp.send_message(message, from_addr=sender, to_addrs=[env["ALERT_EMAIL"].strip()])
    except PollerError:
        raise
    except Exception as exc:  # SMTP exceptions vary by provider and Python version.
        raise PollerError(f"SMTP notification failed: {type(exc).__name__}") from exc


def run(
    env: Mapping[str, str] | None = None,
    client_factory: Callable[..., Any] = Client,
    smtp_factory: Callable[..., Any] = smtplib.SMTP,
) -> int:
    """Run one poll; return 0 on success and 1 on an operational failure."""
    settings = env if env is not None else os.environ
    token = _required(settings, "HCLOUD_TOKEN")
    names = parse_server_types(settings.get("POLL_SERVER_TYPES", ""))
    locations = parse_csv(settings.get("POLL_LOCATION", DEFAULT_LOCATION))
    try:
        client = client_factory(token=token)
        results = check_availability(client, names, locations)
        matches = [item for item in results if item.available]
        if not matches:
            print(f"No configured Hetzner server types reported available in {', '.join(locations)}.")
            return 0
        sender = _required(settings, "SMTP_FROM")
        recipient = _required(settings, "ALERT_EMAIL")
        send_email(build_message(matches, sender, recipient), settings, smtp_factory)
        print(f"Notification sent for {len(matches)} available server type/location pair(s).")
        return 0
    except PollerError as exc:
        print(f"Availability poll failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Availability poll failed: {type(exc).__name__}", file=sys.stderr)
        return 1


def main() -> int:
    load_environment()
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
