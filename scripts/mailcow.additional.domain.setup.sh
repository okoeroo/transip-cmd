#!/bin/bash

echo

echo -n "What is the new domain? "
read DOMAIN

echo -n "What is the mail host? "
read MAILHOST


echo "Changing ${DOMAIN}"
echo "Mail host ${MAILHOST}"
echo "Continue? y/n "


if [ -z ${DOMAIN} ]; then
    echo "Error: no domain provided as argument"
    exit 1
fi


echo "List domain ${DOMAIN}"
./transip-cmd.py \
    --login okoeroo --private-key keys/gamora.api.key \
    --domain "${DOMAIN}" \
    --cmd list

sleep 1


echo "==== Adding config"

./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
    --cmd add --name '@' --expire 300 --type CAA --content "0 iodef \"mailto:abuse@koeroo.net\""

./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
    --cmd add --name '@' --expire 300 --type CAA --content "0 issue \"letsencrypt.org\""

./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
    --cmd add --name '@' --expire 300 --type TXT --content "v=spf1 mx -all"

#./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
#    --cmd add --name 'mail' --expire 300 --type CNAME --content "mail.koeroo.net."

./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
    --cmd add --name '@' --expire 300 --type MX --content "10 ${MAILHOST}."

./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
    --cmd add --name 'autoconfig' --expire 300 --type CNAME --content "${MAILHOST}."

./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
    --cmd add --name 'autodiscover' --expire 300 --type CNAME --content "${MAILHOST}."

./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
    --cmd add --name '_dmarc' --expire 300 --type CNAME --content "_dmarc.koeroo.net."


echo -n "Copy DKIM key here, or hit enter dkim2022._domainkey? "
read DKIMKEY
echo
echo "Got \"${DKIMKEY}\""
if [ -z ${DKIMKEY} ]; then
    echo "skipping dkim config"
else
    ./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
        --cmd add --name 'dkim2022._domainkey' --expire 300 --type TXT --content "${DKIMKEY}"
fi

#./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
#    --cmd add --name 'dane_mail' --expire 300 --type TLSA --content "2 1 1 8D02536C887482BC34FF54E41D2BA659BF85B341A0A20AFADB5813DCFBCF286D"
#
#HASH_3_1_1=$(echo | openssl s_client -connect ${MAILHOST}:25 -starttls smtp 2>/dev/null | openssl x509  -pubkey -noout | openssl pkey -pubin -outform DER | openssl sha256 | cut -d" " -f 2)
#
#./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
#    --cmd add --name 'dane_mail' --expire 300 --type TLSA --content "3 1 1 ${HASH_3_1_1}"

./transip-cmd.py --login okoeroo --private-key keys/gamora.api.key --domain "${DOMAIN}" \
    --cmd add --name '_smtp._tls' --expire 300 --type TXT --content "v=TLSRPTv1; rua=mailto:abuse@koeroo.net"


echo "List domain ${DOMAIN}"
./transip-cmd.py \
    --login okoeroo --private-key keys/gamora.api.key \
    --domain "${DOMAIN}" \
    --cmd list

