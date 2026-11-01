#!/usr/bin/env python3
import sys
import os
import argparse
import re
from datetime import datetime, timezone
from pyDANETLSA import DANETLSA, DANETLSAConnectionError, TLSAResolutionError, TLSAValidationError, str_to_DANETLS_protocol
import transip


def check_correctness(parser, args):
    if args.cmd is None:
        print("= Error: No cmd given")
        print("---")
        parser.print_help()
        return False

    # danetls specific
    elif args.cmd == 'danetlsa' and args.fqdn is None:
        print("= Error: cmd 'danetls' requires --fqdn")
        print("---")
        parser.print_help()
        return False

    elif args.cmd == 'danetlsa' and args.port is None:
        print("= Error: cmd 'danetls' requires --port")
        print("---")
        parser.print_help()
        return False

    elif args.cmd == 'danetlsa' and args.protocol is None:
        print("= Error: cmd 'danetls' requires --protocol")
        print("---")
        parser.print_help()
        return False

    elif args.cmd == 'danetlsa' and (args.protocol == 'pem' or args.protocol == 'der') and args.certfile is None:
        print("= Error: cmd 'danetls' using --protocol with 'pem' or 'der' requires --certfile to be set")
        print("---")
        parser.print_help()
        return False

    # other
    elif args.cmd in ('add', 'remove', 'list', 'danetlsa', 'mtasts') and not (args.domain or '').strip():
        print(f"= Error: cmd '{args.cmd}' requires --domain. Add --domain example.com.")
        print("---")
        parser.print_help()
        return False

    elif (args.cmd in ('add', 'remove', 'danetlsa', 'mtasts')) and args.login is None:
        print("= Error: cmd '{}' requires --login", args.cmd)
        print("---")
        parser.print_help()
        return False

    elif (args.cmd in ('add', 'remove', 'danetlsa', 'mtasts')) and args.privkey is None:
        print("= Error: cmd '{}' requires --private-key", args.cmd)
        print("---")
        parser.print_help()
        return False

    # add and remove
    elif (args.cmd == 'add' or args.cmd == 'remove') and args.name is None:
        print("= Error: cmd '{}' requires --name", args.cmd)
        print("---")
        parser.print_help()
        return False

    elif (args.cmd == 'add' or args.cmd == 'remove') and args.expire is None:
        print("= Error: cmd '{}' requires --expire", args.cmd)
        print("---")
        parser.print_help()
        return False

    elif (args.cmd == 'add' or args.cmd == 'remove') and args.rr_type is None:
        print("= Error: cmd '{}' requires --type", args.cmd)
        print("---")
        parser.print_help()
        return False

    elif (args.cmd == 'add' or args.cmd == 'remove') and args.r_content is None:
        print("= Error: cmd '{}' requires --content", args.cmd)
        print("---")
        parser.print_help()
        return False

    return True

def argparsing(exec_file):
    parser = argparse.ArgumentParser(exec_file)
    parser.add_argument("--cmd",
                        choices=['add', 'remove', 'list', 'danetlsa', 'mtasts'],
                        dest='cmd',
                        help="The used command.",
                        default=None,
                        type=str)
    parser.add_argument("--ut",
                        choices=['tcp', 'udp'],
                        dest='tcpudp',
                        help="Transport protocol for the generated TLSA record (default: tcp).",
                        default='tcp',
                        type=str)
    parser.add_argument("--protocol",
                        choices=['tls', 'imap', 'smtp', 'pop3', 'pem', 'der', 'ftp'],
                        dest='protocol',
                        help="Protocol choice to extract certificate. Plain TLS or \
                              StartTLS with IMAP, SMTP, POP3, FTP, or \
                              by reading a PEM file or DER file.",
                        default=None,
                        type=str)
    parser.add_argument("--certfile",
                        dest='certfile',
                        help="File path to a PEM or DER file to read for DANE TLSA.",
                        default=None,
                        type=str)
    parser.add_argument("--domain",
                        dest='domain',
                        help="Domain, or zone used for TransIP account and domain identification.",
                        default=None,
                        type=str)
    parser.add_argument("--fqdn",
                        dest='fqdn',
                        help="FQDN, full hostname dot domain.",
                        default=None,
                        type=str)
    parser.add_argument("--port",
                        dest='port',
                        help="Port number",
                        default=None,
                        type=int)
    parser.add_argument("--login",
                        dest='login',
                        help="Login username for TransIP.",
                        default=None,
                        type=str)
    parser.add_argument("--private-key",
                        dest='privkey',
                        help="Private key for TransIP.",
                        default=None,
                        type=str)
    parser.add_argument("--name",
                        dest='name',
                        help="Resource record name.",
                        default=None,
                        type=str)
    parser.add_argument("--expire",
                        dest='expire',
                        help="Resource record expiration time in seconds.",
                        default=None,
                        type=int)
    parser.add_argument("--type",
                        dest='rr_type',
                        help="Resource record type, e.g. A, AAAA, TLSA, CNAME, TXT, MX, etc.",
                        default=None,
                        type=str)
    parser.add_argument("--content",
                        dest='r_content',
                        help="Resource record content or data.",
                        default=None,
                        type=str)

    parser.add_argument("--tlsa-311", metavar="HASH|auto", default="auto",
                        help="Calculate the leaf SPKI hash (auto, default), or verify a supplied hash.")
    parser.add_argument("--tlsa-211", metavar="HASH|auto",
                        help="Also publish the issuing CA SPKI hash: auto or a verified supplied hash.")
    args = parser.parse_args()
    if not check_correctness(parser, args):
        sys.exit(1)

    return args

def search_record(domain, name=None, expire=None, rr_type=None, r_content=None):
    records = domain.dns.list()

    # Trapdoor search algo
    res = []
    for record in records:
        if name is not None and name != record.name:
            continue
        if expire is not None and expire != record.expire:
            continue
        if rr_type is not None and rr_type != record.type:
            continue
        if r_content is not None and r_content != record.content:
            continue

        dns_entry_data = {
            "name": record.name,
            "expire": record.expire,
            "type": record.type,
            "content": record.content
        }
        res.append(dns_entry_data)
    return res

def list_records(domain):
    records = search_record(domain)

    for record in records:
        print(f"{record['name']}  {record['expire']}  {record['type']}  {record['content']}")

def remove_record(domain, name=None, expire=None, rr_type=None, r_content=None):
    dns_entry_data = {
        "name": name,
        "expire": expire,
        "type": rr_type,
        "content": r_content
    }
    return domain.dns.delete(dns_entry_data)

def add_record(domain, name=None, expire=None, rr_type=None, r_content=None):
    dns_entry_data = {
        "name": name,
        "expire": expire,
        "type": rr_type,
        "content": r_content
    }
    return domain.dns.create(dns_entry_data)

def ensure_mtasts(domain):
    """Keep one valid MTA-STS announcement; do not rotate its id on every run."""
    records = search_record(domain, name="_mta-sts")
    if any(r["type"] == "CNAME" for r in records):
        raise ValueError("_mta-sts is a CNAME; no records changed")
    records = [r for r in records if r["type"] == "TXT"]
    pattern = re.compile(r"^v=STSv1;\s*id=([A-Za-z0-9]{1,32});?\s*$")
    valid = [(pattern.fullmatch(r["content"]), r) for r in records]
    valid = [(match, r) for match, r in valid if match]
    if valid:
        # IDs are opaque; lexicographic order selects the latest timestamp-style ID.
        keeper = max(valid, key=lambda item: item[0].group(1))[1]
        if sum(r == keeper for r in records) > 1:
            raise ValueError("Identical duplicate MTA-STS records cannot be safely deleted individually")
    else:
        keeper = dict(name="_mta-sts", expire=300, type="TXT",
                      content="v=STSv1; id=" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
        domain.dns.create(keeper)
    for record in records:
        if record != keeper:
            domain.dns.delete(record)
            print("Removed duplicate/invalid _mta-sts: " + record["content"])
    current = search_record(domain, name="_mta-sts", rr_type="TXT")
    if len(current) != 1 or current[0]["content"] != keeper["content"]:
        raise ValueError("MTA-STS verification did not return exactly one expected record; inspect DNS")
    print("MTA-STS: exactly one record: " + keeper["content"])
    return keeper


def update_danetlsa(domain, args):
    protocol = str_to_DANETLS_protocol(args.protocol)
    d = DANETLSA(
        fqdn=args.fqdn,
        port=args.port,
        domain=args.domain,
        transport_proto=args.tcpudp,
        app_protocol=protocol,
        certfile=args.certfile if args.protocol in ('pem', 'der') else None,
    )
    if args.tcpudp != "tcp" and args.protocol not in ("pem", "der"):
        raise TLSAValidationError("Live certificate probing supports TCP only; use --ut tcp")
    d.connect()
    desired = d.tlsa_rdata_3_1_1(getattr(args, "tlsa_311", "auto"))
    print(f"Validated leaf: {desired}")

    # Validate before any DNS mutation; a mismatch must not publish either record.
    anchor_record = None
    if getattr(args, "tlsa_211", None):
        anchor_record = d.tlsa_rdata_2_1_1(args.tlsa_211)
        print(f"Validated CA: {anchor_record}")

    target, chain = d.tlsa_target()
    print("TLSA target: " + " -> ".join(chain))
    zone = args.domain.rstrip(".").lower()
    owner = target.rstrip(".").lower()
    if owner == zone:
        name = "@"
    elif owner.endswith("." + zone):
        name = owner[:-(len(zone) + 1)]
    else:
        raise TLSAResolutionError(
            f"TLSA target {target} is outside --domain {args.domain}; "
            "no records changed. Select the target's managed zone with --domain."
        )

    # Check the provider as well: DNS caches must not cause a write over a CNAME.
    records = search_record(domain, name=name)
    if any(record["type"] == "CNAME" for record in records):
        raise TLSAResolutionError(
            f"Target {target} is still a CNAME in TransIP; no records changed. "
            "Wait for DNS propagation and retry."
        )
    tlsa = [r for r in records if r["type"] == "TLSA"]
    normalized = lambda content: " ".join(content.lower().split())
    matching = [r for r in tlsa if normalized(r["content"]) == normalized(desired)]
    if not matching:
        # Publish first so a failed creation never removes the existing TLSA.
        add_record(domain, name=name, expire=300, rr_type="TLSA", r_content=desired)
        print(f"Added TLSA at {target}")
    else:
        print(f"TLSA at {target} already matches")

    if anchor_record:
        if not any(normalized(r["content"]) == normalized(anchor_record) for r in tlsa):
            add_record(domain, name=name, expire=300, rr_type="TLSA", r_content=anchor_record)
            print(f"Added validated TLSA 2 1 1 at {target}")
        else:
            print(f"TLSA 2 1 1 at {target} already matches")

    # Preserve other usages/selectors and remove only superseded 3 1 1 records.
    for record in tlsa:
        fields = record["content"].split()
        if fields[:3] == ["3", "1", "1"] and normalized(record["content"]) != normalized(desired):
            remove_record(domain, name=name, expire=record["expire"],
                          rr_type="TLSA", r_content=record["content"])
            print(f"Removed superseded TLSA 3 1 1 at {target}")


### MAIN
if __name__ == "__main__":
    args = argparsing(os.path.basename(__file__))

    try:
        # Start TransIP client
        client = transip.TransIP(login=args.login, private_key_file=args.privkey)
        domain = client.domains.get(args.domain)

        # Execute command
        if args.cmd == 'danetlsa':
            update_danetlsa(domain, args)

        elif args.cmd == 'mtasts':
            ensure_mtasts(domain)

        elif args.cmd == 'add':
            add_record(domain, name=args.name,       expire=args.expire,
                               rr_type=args.rr_type, r_content=args.r_content)

        elif args.cmd == 'remove':
            remove_record(domain, name=args.name,       expire=args.expire,
                                  rr_type=args.rr_type, r_content=args.r_content)

        elif args.cmd == 'list':
            list_records(domain)

        else:
            print("Not implemented")

    except (DANETLSAConnectionError, TLSAResolutionError, TLSAValidationError, ValueError) as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    except transip.exceptions.TransIPHTTPError as err:
        print(f"TransIPHTTPError: {err}", file=sys.stderr)
        sys.exit(1)
