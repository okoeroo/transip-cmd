#!/usr/bin/env python3
import sys
import os
import argparse
from pyDANETLSA import DANETLSA, DANETLSAConnectionError, TLSAResolutionError, str_to_DANETLS_protocol
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
    elif args.cmd in ('add', 'remove', 'list', 'danetlsa') and not (args.domain or '').strip():
        print(f"= Error: cmd '{args.cmd}' requires --domain. Add --domain example.com.")
        print("---")
        parser.print_help()
        return False

    elif (args.cmd == 'add' or args.cmd == 'remove' or args.cmd == 'danetlsa') and args.login is None:
        print("= Error: cmd '{}' requires --login", args.cmd)
        print("---")
        parser.print_help()
        return False

    elif (args.cmd == 'add' or args.cmd == 'remove' or args.cmd == 'danetlsa') and args.privkey is None:
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
                        choices=['add', 'remove', 'list', 'danetlsa'],
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
    d.connect()

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
    desired = d.tlsa_rdata_3_1_1()
    tlsa = [r for r in records if r["type"] == "TLSA"]
    normalized = lambda content: " ".join(content.lower().split())
    matching = [r for r in tlsa if normalized(r["content"]) == normalized(desired)]
    if not matching:
        # Publish first so a failed creation never removes the existing TLSA.
        add_record(domain, name=name, expire=300, rr_type="TLSA", r_content=desired)
        print(f"Added TLSA at {target}")
    else:
        print(f"TLSA at {target} already matches")

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

    except (DANETLSAConnectionError, TLSAResolutionError) as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    except transip.exceptions.TransIPHTTPError as err:
        print(f"TransIPHTTPError: {err}", file=sys.stderr)
        sys.exit(1)
