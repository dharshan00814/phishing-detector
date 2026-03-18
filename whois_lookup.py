import argparse
from datetime import datetime
from typing import Any

import whois


def _first_value(value: Any) -> Any:
    """Return the first non-empty value if a WHOIS field is a list/tuple/set."""
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if item:
                return item
        return None
    return value


def _format_date(value: Any) -> str:
    """Convert WHOIS date fields to a readable yyyy-mm-dd format."""
    value = _first_value(value)
    if not value:
        return "N/A"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return str(value)


def lookup_domain(domain: str) -> dict:
    """Fetch WHOIS data for a domain and return normalized fields."""
    data = whois.whois(domain)

    return {
        "domain": _first_value(data.domain_name) or domain,
        "registrar": _first_value(data.registrar) or "N/A",
        "creation_date": _format_date(data.creation_date),
        "expiration_date": _format_date(data.expiration_date),
        "updated_date": _format_date(data.updated_date),
        "status": _first_value(data.status) or "N/A",
        "name_servers": data.name_servers if data.name_servers else [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="WHOIS lookup utility")
    parser.add_argument("domain", help="Domain to query, e.g. google.com")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//", 1)[1].split("/", 1)[0]
    if domain.startswith("www."):
        domain = domain[4:]

    try:
        result = lookup_domain(domain)
    except Exception as exc:
        print(f"WHOIS lookup failed: {exc}")
        raise SystemExit(1)

    print("WHOIS Lookup Result")
    print("-" * 50)
    print(f"Domain         : {result['domain']}")
    print(f"Registrar      : {result['registrar']}")
    print(f"Created On     : {result['creation_date']}")
    print(f"Expires On     : {result['expiration_date']}")
    print(f"Updated On     : {result['updated_date']}")
    print(f"Status         : {result['status']}")

    ns = result["name_servers"]
    if ns:
        print("Name Servers   :")
        if isinstance(ns, (list, tuple, set)):
            for item in ns:
                print(f"  - {item}")
        else:
            print(f"  - {ns}")
    else:
        print("Name Servers   : N/A")


if __name__ == "__main__":
    main()
