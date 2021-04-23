# transip-cmd


usage: transip-test.py [-h] [--cmd {add,remove,danetlsa}] [--ut {tcp,udp}] [--protocol {tls,imap,smtp,pop3}] [--fqdn FQDN] [--port PORT] [--login LOGIN] [--private-key PRIVKEY]

optional arguments:
  -h, --help            show this help message and exit
  --cmd {add,remove,danetlsa}
                        The used command.
  --ut {tcp,udp}        For DANE TLSA set udp or tcp. - Needs fix in pyDANETLSA.
  --protocol {tls,imap,smtp,pop3}
                        Protocol choice to extract certificate. Plain TLS or StartTLS with IMAP, SMTP, POP3.
  --fqdn FQDN           FQDN, full hostname dot domain.
  --port PORT           Port number
  --login LOGIN         Login username for TransIP.
  --private-key PRIVKEY
                        Private key for TransIP.
