from dnslib import QTYPE

# Fake DNS zone for corp.local. 
# Maps each hostname to its record type and value.
ZONE = {
    "admin.corp.local.": {"A": "192.168.2.10"},
    "db01.corp.local.": {"A": "192.168.2.11"},
    "vpn.corp.local.": {"A": "192.168.2.12"},
    "flag.corp.local.": {"TXT": "flag{placeholder}"},
}

# Looks up a record in the zone for the given query name and type.
# Returns the record's value, or None if there's no match.
def lookup(qname: str, qtype: int) -> str | None:
    record = ZONE.get(qname)
    if record is None:
        return None
    return record.get(QTYPE.get(qtype))