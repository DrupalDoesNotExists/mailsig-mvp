import re
from typing import Tuple

from dns import resolver, rdata, exception

_resolver = resolver.Resolver()
pattern = re.compile(r'mailsig:([^,]+)(?:,([^,]+))?')


def parse_txt(record: str) -> Tuple[str | None] | None:
    match = pattern.search(record)
    return match.groups() if match else None


def fetch_record_txt(record: rdata.Rdata) -> str:
    return "".join([string.decode() for string in record.strings])


def query_records(domain: str) -> Tuple[str | None] | None:
    try:
        records = _resolver.resolve(domain, 'TXT')
    except exception.DNSException as error:
        return None
    for record in records:
        signatures = parse_txt(fetch_record_txt(record))
        if signatures:
            return signatures
