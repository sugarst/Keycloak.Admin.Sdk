#!/bin/sh
set -eu
export KRB5_CONFIG=/kerberos/krb5.conf
export KRB5_KDC_PROFILE=/kerberos/kdc.conf
export KRB5CCNAME=FILE:/tmp/sdk-kerberos-ccache
kdb5_util create -s -P "$(head -c 24 /dev/urandom | base64)" >/dev/null
kadmin.local -q 'addprinc -randkey HTTP/localhost@SDK.TEST' >/dev/null 2>&1
kadmin.local -q 'addprinc -randkey kerberos-user@SDK.TEST' >/dev/null 2>&1
kadmin.local -q 'ktadd -k /kerberos/service.keytab HTTP/localhost@SDK.TEST' >/dev/null 2>&1
kadmin.local -q 'ktadd -k /kerberos/user.keytab kerberos-user@SDK.TEST' >/dev/null 2>&1
chmod 644 /kerberos/service.keytab
krb5kdc -n >/dev/null 2>&1 &
for attempt in 1 2 3 4 5; do
    if kinit -k -t /kerberos/user.keytab kerberos-user@SDK.TEST 2>/dev/null; then break; fi
    sleep 1
done
klist -s
exec python3 /fixture/ticket.py
