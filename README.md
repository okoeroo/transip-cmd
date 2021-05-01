# transip-cmd
Wrapper around the TransIP API using python-transip. It also allows for automatic detecting of the TLSA configuration through pyDANETLSA.

## Requirements
* pip install python-transip
* pip install pyDANETLSA (>= 0.1.0)


## Usage:
```
usage: transip-cmd.py [-h] [--cmd {add,remove,list,danetlsa}] [--ut {tcp,udp}]
                      [--protocol {tls,imap,smtp,pop3,pem,der,ftp}] 
                      [--certfile CERTFILE] [--domain DOMAIN] [--fqdn FQDN]
                      [--port PORT] [--login LOGIN] [--private-key PRIVKEY]
                      [--name NAME] [--expire EXPIRE] [--type RR_TYPE]
                      [--content R_CONTENT]

optional arguments:
  -h, --help            show this help message and exit
  --cmd {add,remove,list,danetlsa}
                        The used command.
  --ut {tcp,udp}        For DANE TLSA set udp or tcp. - Needs fix in pyDANETLSA.
  --protocol {tls,imap,smtp,pop3,pem,der,ftp}
                        Protocol choice to extract certificate. Plain TLS or StartTLS with IMAP, SMTP, POP3, FTP, or by reading a PEM file or DER file.
  --certfile CERTFILE   File path to a PEM or DER file to read for DANE TLSA.
  --domain DOMAIN       Domain, or zone used for TransIP account and domain identification.
  --fqdn FQDN           FQDN, full hostname dot domain.
  --port PORT           Port number
  --login LOGIN         Login username for TransIP.
  --private-key PRIVKEY
                        Private key for TransIP.
  --name NAME           Resource record name.
  --expire EXPIRE       Resource record expiration time in seconds.
  --type RR\_TYPE        Resource record type, e.g. A, AAAA, TLSA, CNAME, TXT, MX, etc.
  --content R\_CONTENT   Resource record content or data.
```
