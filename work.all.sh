#!/bin/bash -x

# Calculate both records from each service, or supply verified SPKI pins.
# A shared pin must match every service in this script.
TLSA_311_SHA256=${TLSA_311_SHA256:-auto}
TLSA_211_SHA256=${TLSA_211_SHA256:-auto}

./transip-cmd.py --cmd list     --domain koeroo.com --login okoeroo --private-key /home/okoeroo/keys/transip.private.key
./transip-cmd.py --cmd add      --domain koeroo.com --name test1 --expire 777 --type TXT --content "test 1 2 3" --login okoeroo --private-key /home/okoeroo/keys/transip.private.key

echo
./transip-cmd.py --cmd danetlsa --ut tcp --tlsa-311 "$TLSA_311_SHA256" --tlsa-211 "$TLSA_211_SHA256" --domain koeroo.net --protocol imap --fqdn  smtp.koeroo.net --port 143 --login okoeroo --private-key /home/okoeroo/keys/transip.private.key
./transip-cmd.py --cmd danetlsa --ut tcp --tlsa-311 "$TLSA_311_SHA256" --tlsa-211 "$TLSA_211_SHA256" --domain koeroo.net --protocol smtp --fqdn  smtp.koeroo.net --port  25 --login okoeroo --private-key /home/okoeroo/keys/transip.private.key
./transip-cmd.py --cmd danetlsa --ut tcp --tlsa-311 "$TLSA_311_SHA256" --tlsa-211 "$TLSA_211_SHA256" --domain koeroo.net --protocol tls  --fqdn  smtp.koeroo.net --port 465 --login okoeroo --private-key /home/okoeroo/keys/transip.private.key
./transip-cmd.py --cmd danetlsa --ut tcp --tlsa-311 "$TLSA_311_SHA256" --tlsa-211 "$TLSA_211_SHA256" --domain koeroo.net --protocol tls  --fqdn  smtp.koeroo.net --port 993 --login okoeroo --private-key /home/okoeroo/keys/transip.private.key
./transip-cmd.py --cmd danetlsa --ut tcp --tlsa-311 "$TLSA_311_SHA256" --tlsa-211 "$TLSA_211_SHA256" --domain koeroo.net --protocol tls  --fqdn nextcloud.koeroo.net --port 443 --login okoeroo --private-key /home/okoeroo/keys/transip.private.key

dig TXT test1.koeroo.com  @ns0.transip.net
echo "Sleeping 10"
sleep 10
dig TXT test1.koeroo.com  @ns0.transip.net
echo
#./transip-cmd.py --cmd remove   --domain koeroo.com --name test1 --expire 777 --type TXT --content "test 1 2 3" --login okoeroo --private-key /home/okoeroo/keys/transip.private.key
echo "Sleeping 5"
sleep 5
dig TXT test1.koeroo.com  @ns0.transip.net
echo

./transip-cmd.py --cmd danetlsa --ut tcp --tlsa-311 "$TLSA_311_SHA256" --tlsa-211 "$TLSA_211_SHA256" --domain koeroo.net --protocol smtp --fqdn  smtp.koeroo.net --port  25 --login okoeroo --private-key /home/okoeroo/keys/transip.private.key


./transip-cmd.py --cmd mtasts --domain koeroo.net --login okoeroo --private-key /home/okoeroo/keys/transip.private.key
./transip-cmd.py --cmd add --domain koeroo.net  --name _smtp._tls --expire 300 --type TXT --content "v=TLSRPTv1; rua=mailto:abuse@koeroo.net"  --login okoeroo --private-key /home/okoeroo/keys/transip.private.key

