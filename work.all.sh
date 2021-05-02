#!/bin/bash -x

./transip-cmd.py --cmd add      --domain koeroo.com --name test1 --expire 777 --type TXT --content "test 1 2 3" --login okoeroo --private-key keys/gamora.api.key

echo
./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol imap --fqdn  smtp.koeroo.net --port 143 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol smtp --fqdn  smtp.koeroo.net --port  25 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol tls  --fqdn  smtp.koeroo.net --port 465 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol tls  --fqdn  smtp.koeroo.net --port 993 --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol tls  --fqdn cloud.koeroo.net --port 443 --login okoeroo --private-key keys/gamora.api.key

dig TXT test1.koeroo.com  @ns0.transip.net
echo "Sleeping 30"
sleep 30
dig TXT test1.koeroo.com  @ns0.transip.net
echo
#./transip-cmd.py --cmd remove   --domain koeroo.com --name test1 --expire 777 --type TXT --content "test 1 2 3" --login okoeroo --private-key keys/gamora.api.key
echo "Sleeping 15"
sleep 15
dig TXT test1.koeroo.com  @ns0.transip.net
echo

./transip-cmd.py --cmd danetlsa --domain koeroo.net --protocol smtp --fqdn  smtp.koeroo.net --port  25 --login okoeroo --private-key keys/gamora.api.key --certfile certs/letsencrypt_R3_CA.pem


./transip-cmd.py --cmd add --domain koeroo.net  --name _mta-sts   --expire 300 --type TXT --content "v=STSv1; id=$(date "+%y%m%d%H%M%S")"  --login okoeroo --private-key keys/gamora.api.key
./transip-cmd.py --cmd add --domain koeroo.net  --name _smtp._tls --expire 300 --type TXT --content "v=TLSRPTv1; rua=mailto:abuse@koeroo.net"  --login okoeroo --private-key keys/gamora.api.key

