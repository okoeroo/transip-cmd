./transip-cmd.py --cmd danetlsa --protocol imap --fqdn  smtp.koeroo.net --port 143 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --protocol smtp --fqdn  smtp.koeroo.net --port  25 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --protocol tls  --fqdn  smtp.koeroo.net --port 465 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --protocol tls  --fqdn  smtp.koeroo.net --port 993 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --protocol tls  --fqdn cloud.koeroo.net --port 443 --login okoeroo --private-key keys/gamora.api.key
