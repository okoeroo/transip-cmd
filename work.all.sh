./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol imap --fqdn  smtp.koeroo.net --port 143 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol smtp --fqdn  smtp.koeroo.net --port  25 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol tls  --fqdn  smtp.koeroo.net --port 465 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol tls  --fqdn  smtp.koeroo.net --port 993 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol tls  --fqdn cloud.koeroo.net --port 443 --login okoeroo --private-key keys/gamora.api.key

