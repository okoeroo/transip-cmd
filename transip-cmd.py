#!/usr/bin/env python3
import sys
import os
import argparse
import pyDANETLSA
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
    elif (args.cmd == 'add' or args.cmd == 'remove' or args.cmd == 'danetlsa') and args.domain is None:
        print("= Error: cmd '{}' requires --domain", args.cmd)
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
                        choices=['tls', 'imap', 'smtp', 'pop3', 'pem', 'der'],
                        dest='protocol',
                        help="Protocol choice to extract certificate. Plain TLS \
                              or StartTLS with IMAP, SMTP, POP3, PEM file, DER file.",
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


def update_danetlsa(domain, args):
    if args.protocol == 'tls':
        protocol = pyDANETLSA.DANETLSA_TLS
    if args.protocol == 'imap':
        protocol = pyDANETLSA.DANETLSA_IMAP
    if args.protocol == 'smtp':
        protocol = pyDANETLSA.DANETLSA_SMTP
    if args.protocol == 'pop3':
        protocol = pyDANETLSA.DANETLSA_POP3
    if args.protocol == 'pem':
        protocol = pyDANETLSA.DANETLSA_PEM
    if args.protocol == 'der':
        protocol = pyDANETLSA.DANETLSA_DER

    if args.protocol == 'der' or args.protocol == 'pem':
        # Run DANE TLSA analyser based on the provided certificate file
        d = pyDANETLSA.danetlsa(fqdn=args.fqdn, port=args.port,
                                protocol=protocol, certfile=args.certfile)
        d.engage()
    else:
        # Run DANE TLSA analyser based on the pyDANETLSA analyser
        d = pyDANETLSA.danetlsa(fqdn=args.fqdn, port=args.port,
                                protocol=protocol)
        d.engage()

    # Search for similar record, and regardless of exact value.
    res = search_record(domain, name=d.tlsa_rr_name_host(), rr_type='TLSA')

    # Remove all instances of these
#    for dns_entry_data in res:
#        remove_record(domain, name=dns_entry_data['name'],
#                              expire=dns_entry_data['expire'],
#                              rr_type=dns_entry_data['type'],
#                              r_content=dns_entry_data['content'])

    # Add new updated record, using the pyDANETLSA analyses
    add_record(domain, name=d.tlsa_rr_name_host(),
                       expire=300,
                       rr_type="TLSA",
                       r_content=d.tlsa_rdata_3_1_1())


### MAIN
if __name__ == "__main__":
    args = argparsing(os.path.basename(__file__))

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

    else:
        print("Not implemented")
