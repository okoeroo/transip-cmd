#!/usr/bin/env python3
import sys
import argparse
import pyDANETLSA
import transip


def check_correctness(parser, args):
    if args.cmd is None:
        print("Error: No cmd given")
        print("---")
        parser.print_help()
        sys.exit(1)

    elif args.cmd == 'danetls' and \
        (args.fqdn is None or \
         args.port is None or \
         args.protocol is None or \
         args.privkey is None or \
         args.login is None):
        print("cmd 'danetls' requires --fqdn, --port, --protocol, --private-key and --login")
        print("---")
        parser.print_help()
        sys.exit(1)

#    if args.protocol is None:
#        parser.print_help()
#        sys.exit(1)
#    if args.fqdn is None:
#        parser.print_help()
#        sys.exit(1)
#    if args.port is None:
#        parser.print_help()
#        sys.exit(1)
#    if args.login is None:
#        parser.print_help()
#        sys.exit(1)
#    if args.privkey is None:
#        parser.print_help()
#        sys.exit(1)
#    if args.cmd is None:
#        parser.print_help()
#        sys.exit(1)


    return args

def argparsing(exec_file):
    parser = argparse.ArgumentParser(exec_file)
    parser.add_argument("--cmd",
                        choices=['add', 'remove', 'danetlsa'],
                        dest='cmd',
                        help="The used command.",
                        default=None,
                        type=str)
    parser.add_argument("--ut",
                        choices=['tcp', 'udp'],
                        dest='tcpudp',
                        help="For DANE TLSA set udp or tcp. - Needs fix in pyDANETLSA.",
                        default='tcp',
                        type=str)
    parser.add_argument("--protocol",
                        choices=['tls', 'imap', 'smtp', 'pop3'],
                        dest='protocol',
                        help="Protocol choice to extract certificate. Plain TLS \
                              or StartTLS with IMAP, SMTP, POP3.",
                        default=None)
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

def remove_record(domain, name=None, expire=None, rr_type=None, r_content=None):
    dns_entry_data = {
        "name": name,
        "expire": expire,
        "type": rr_type,
        "content": r_content
    }
    domain.dns.delete(dns_entry_data)

def add_record(domain, name=None, expire=None, rr_type=None, r_content=None):
    dns_entry_data = {
        "name": name,
        "expire": expire,
        "type": rr_type,
        "content": r_content
    }
    return domain.dns.create(dns_entry_data)


def update_danetlsa(args):
    fqdn = args.fqdn
    port = args.port

    if args.protocol == 'tls':
        protocol = pyDANETLSA.DANETLSA_TLS
    if args.protocol == 'imap':
        protocol = pyDANETLSA.DANETLSA_IMAP
    if args.protocol == 'smtp':
        protocol = pyDANETLSA.DANETLSA_SMTP
    if args.protocol == 'pop3':
        protocol = pyDANETLSA.DANETLSA_POP3

    # Start TransIP client
    client = transip.TransIP(login=args.login, private_key_file=args.privkey)

    # Run DANE TLSA analyser
    d = pyDANETLSA.danetlsa(fqdn=fqdn, port=port, protocol=protocol)
    d.connect()
    d.process_pubkey_hex()

    # Use host/domain splitter from pyDANETLSA
    domain = client.domains.get(d.domain)

    # Search for similar record, and regardless of exact value.
    res = search_record(domain, name=d.tlsa_rr_name_host(), rr_type='TLSA')

    # Remove all instances of these
    for dns_entry_data in res:
        remove_record(domain, name=dns_entry_data['name'],
                              expire=dns_entry_data['expire'],
                              rr_type=dns_entry_data['type'],
                              r_content=dns_entry_data['content'])
    else:
        print("Nothing to remove")

    # Add new updated record, using the pyDANETLSA analyses
    ret = add_record(domain, name=d.tlsa_rr_name_host(),
                       expire=300,
                       rr_type="TLSA",
                       r_content=d.tlsa_rdata_3_1_1())
    print(ret)
    print("Added")



### MAIN
if __name__ == "__main__":
    args = argparsing('transip-test.py')

    if args.cmd == 'danetlsa':
        update_danetlsa(args)
    else:
        print("Not implemented")
