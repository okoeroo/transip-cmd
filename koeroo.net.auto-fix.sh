#!/bin/bash -x

source .venv/bin/activate

# Calculate both records from each service, or supply verified SPKI pins.
# A shared pin must match every service in this script.
TLSA_311_SHA256=${TLSA_311_SHA256:-auto}
TLSA_211_SHA256=${TLSA_211_SHA256:-auto}

./transip-cmd.py --cmd danetlsa --ut tcp --tlsa-311 "$TLSA_311_SHA256" --tlsa-211 "$TLSA_211_SHA256" --domain koeroo.net --protocol smtp --fqdn  smtp.koeroo.net --port  25 --login okoeroo --private-key /home/okoeroo/keys/transip.private.key

./transip-cmd.py --cmd danetlsa --ut tcp --tlsa-311 "$TLSA_311_SHA256" --tlsa-211 "$TLSA_211_SHA256" --domain koeroo.net --protocol tls  --fqdn nextcloud.koeroo.net --port 443 --login okoeroo --private-key /home/okoeroo/keys/transip.private.key

./transip-cmd.py --cmd mtasts --domain koeroo.net --login okoeroo --private-key /home/okoeroo/keys/transip.private.key
./transip-cmd.py --cmd add --domain koeroo.net  --name _smtp._tls --expire 300 --type TXT --content "v=TLSRPTv1; rua=mailto:abuse@koeroo.net"  --login okoeroo --private-key /home/okoeroo/keys/transip.private.key

