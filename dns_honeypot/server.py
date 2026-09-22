import socket

from dnslib import DNSRecord, RCODE, RR, QTYPE, A, TXT

from .config import LISTEN_HOST, LISTEN_PORT, UPSTREAM_DNS
from .logger import log_event
from .zone import lookup

# Maps a record type string to the dnslib class used to encode it.
RDATA_TYPES = {
    "A": A,
    "TXT": TXT,
}

# Forwards a war DNS query to the updstram server and returns the raw response.
def forward(data: bytes, upstream: tuple[str, int]) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fsock:
        fsock.settimeout(2)
        fsock.sendto(data, upstream)
        response, _ = fsock.recvfrom(512)
        return response

# Handles one incoming DNS query: parsesit, logs it, then either answers
# it directly from the fake zone ot forwards it upstream and relays the reply.
def handle_query(data: bytes, addr: tuple[str, int], sock: socket.socket) -> None:
    client_ip = addr[0]

    # Parse the raw quuery bytes. Drop anything that doesn't parse as DNS.
    try:
        request = DNSRecord.parse(data)
    except Exception:
        log_event("honeypot.dns.malformed", src_ip=client_ip)
        return

    question = request.q
    qname = str(question.qname)
    qtype = question.qtype  

    # Log every query, whether it's answered locally or forwarded.
    log_event(
        "honeypot.dns.query",
        src_ip=client_ip,
        qname=qname,
        qtype=qtype,
    )

    value = lookup(qname, qtype)

    # In-zone match: build and send an authoritative answer.
    if value is not None:
        reply = request.reply()
        rdata_cls = RDATA_TYPES[QTYPE.get(qtype)]
        reply.add_answer(RR(
            rname=question.qname,
            rtype=qtype,
            rclass=1,
            ttl=300,
            rdata=rdata_cls(value),
        ))
        sock.sendto(reply.pack(), addr)
        return

    # Not in the zone: forward the query upstream and relay the real answer back.
    try:
        repsonse = forward(data, UPSTREAM_DNS)
    except (socket.timeout, OSError):
        log_event("honeypot.dns.forward_failed", src_ip=client_ip, qname=qname)
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        sock.sendto(reply.pack(), addr)
        return
    sock.sendto(repsonse, addr)

    

# Binds the UDP socket and loops forever, handling one query at a time.
def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    print(f"dns honeypot listening on {LISTEN_HOST}:{LISTEN_PORT}...")

    while True:
        data, addr = sock.recvfrom(512)  
        handle_query(data, addr, sock)
