#!/usr/local/bin/bash

# pw userdel -r -n alias
# pw userdel -r -n qmaild
# pw userdel -r -n qmaill
# pw userdel -r -n qmailp
# pw userdel -r -n qmailq
# pw userdel -r -n qmailr
# pw userdel -r -n qmails
# pw groupdel qmail
# pw groupdel qnofiles

if ! [ -d /usr/ports/mail/qmail-tls ]
then
echo "You must have ports added to install qmail"
echo ""
echo "Install Ports?"
read installports
case $installports in
        [nN]*)
            echo "No Probs"
                exit 1
        ;;
        *)
                portsnap fetch extract update
                wait
        ;;
esac
fi


pw groupadd qnofiles -g 81
pw useradd -g qnofiles -d /var/qmail/alias -m -n alias -u 81
pw useradd -g qnofiles -d /var/qmail -n qmaild -u 82
pw useradd -g qnofiles -d /var/qmail -n qmaill -u 83
pw useradd -g qnofiles -d /var/qmail -n qmailp -u 84
pw groupadd qmail -g 82
pw useradd -g qmail -d /var/qmail -n qmailq -u 85
pw useradd -g qmail -d /var/qmail -n qmailr -u 86
pw useradd -g qmail -d /var/qmail -n qmails -u 87

cd ~alias; touch .qmail-postmaster .qmail-mailer-daemon .qmail-root
chmod 644 ~alias/.qmail*


pw groupadd vchkpw -g 89
pw useradd -g vchkpw -m -d /usr/local/vpopmail -n vpopmail -u 89

echo 'DEFAULT_VERSIONS+=ssl=openssl' > /etc/make.conf
echo 'QMAIL_SLAVEPORT=tls' >> /etc/make.conf


cd /usr/ports/mail/qmail-tls 
echo "Ensure to check SMTP_AUTH_PATCH. Click Enter to continue..."
read clickenter
make config 
make install

cp /var/qmail/boot/home /var/qmail/rc
mv /usr/lib/sendmail /usr/lib/sendmail.old
mv /usr/sbin/sendmail /usr/sbin/sendmail.old
cd /usr/lib/
ln -s /var/qmail/bin/sendmail
cd /usr/sbin/
ln -s /var/qmail/bin/sendmail
cd /usr/local/sbin
ln -s /var/qmail/bin/sendmail




if [ ! -d "/usr/src" ]; then
mkdir -p /usr/src
fi
cp vpopmail-5.4.33.tar.gz /usr/src
cp autorespond.tar.gz /usr/src

cd /usr/src
gzip -dc vpopmail-5.4.33.tar.gz | tar -xf -
cd /usr/src/vpopmail-5.4.33
sed -i '' -e 's/.*bounce-no-mailbox\\n.*/fprintf(fs, "| %s\/bin\/vdelivermail '"''"' %s\/domains\/%s\/postmaster\\n", VPOPMAILDIR, dir, domain);/' vpopmail.c

mv ../autorespond.tar.gz .
gzip -dc autorespond.tar.gz | tar -xf -
gcc -Wall -o autorespond autorespond.c
mv autorespond /var/qmail/bin

./configure \
--prefix=/usr/local/vpopmail \
--mandir=/usr/local/vpopmail/man \
--enable-qmaildir=/var/qmail/ \
--enable-qmail-newu=/var/qmail/bin/qmail-newu  \
--enable-qmail-inject=/var/qmail/bin/qmail-inject  \
--enable-qmail-newmrh=/var/qmail/bin/qmail-newmrh  \
--enable-tcprules-prog=/usr/local/bin/tcprules  \
--enable-tcpserver-file=/usr/local/vpopmail/etc/tcp.smtp  \
--enable-clear-passwd  \
--enable-many-domains  \
--enable-qmail-ext  \
--enable-logging=y  \
--enable-auth-logging=y  \
--enable-libdir=/usr/lib/  \
--disable-passwd  \
--enable-domainquotas  \
--enable-roaming-users \
--enable-vpopuser=vpopmail \
--enable-vpopgroup=vchkpw \
--enable-incdir=/usr/local/include

make && make install-strip
pkg install ucspi-tcp
pkg install -y cdb

cat <<EOF


If you have never run the CPAN shell before, just hit enter a few times and it will drop you right to the CPAN prompt.

cpan> install CDB_File
cpan> exit

EOF

perl -MCPAN -e shell


chown root:qmail /var/qmail/bin/qmail-remote
chmod 755 /var/qmail/bin/qmail-remote

cat <<EOF


If you have never run the CPAN shell before, just hit enter a few times and it will drop you right to the CPAN prompt.

cpan> install Mail::DKIM
cpan> quit

EOF

cpan

cd /usr/ports/mail/libdomainkeys
make install


cd /usr/ports/mail/libdkim
make install

# cd /usr/ports/mail/qmail-dk
# make install


/usr/libexec/locate.updatedb
find / -name 'dkimsign.pl' -exec cp "{}" /usr/local/bin/ \;
# /usr/local/bin/dkimsign.pl



echo "ENTER YOUR DOMAIN NAME / SERVER HOST NAME FOR QMAIL"
read MYDOMAINNAME
echo "$MYDOMAINNAME" > /var/qmail/control/me
echo "$MYDOMAINNAME" > /var/qmail/control/defaultdomain
echo "$MYDOMAINNAME" > /var/qmail/control/plusdomain
echo "$MYDOMAINNAME" > /var/qmail/control/rcpthosts
echo "$MYDOMAINNAME" > /var/qmail/control/locals
echo "./Maildir/" > /var/qmail/control/defaultdelivery
echo "1000" > /var/qmail/control/concurrencyremote
echo "1000" > /var/qmail/control/concurrencylocal
echo "120" > /var/qmail/control/queuelifetime


openssl ciphers > /var/qmail/control/tlsclientciphers
openssl ciphers > /var/qmail/control/tlsserverciphers

echo ""
echo "DO YOU HAVE A .key and .crt file to make the servercert.pem file? Y/N"
read HAVECERTFILE
case $addmySUBDOMAIN in
    [yY]*)
        echo "Enter location of .key file"
        read MYKEY
        echo "Enter location of .crt file"
        read MYCERT
        cat $MYKEY $MYCERT > /var/qmail/control/servercert.pem
    ;;
    *)
        cd /usr/ports/mail/qmail-tls
        make certificate
    ;;
esac
chown vpopmail:vchkpw /var/qmail/control/servercert.pem
ln -s /var/qmail/control/servercert.pem /var/qmail/control/clientcert.pem
chown root:qmail /var/qmail/control/clientcert.pem

cd /usr/ports/mail/libdomainkeys/work/libdomaink*
make
cp dktest /usr/local/bin/dktest
chmod 755 /usr/local/bin/dktest


chown root:qmail /var/qmail/bin/qmail-remote
chmod 755 /var/qmail/bin/qmail-remote


mv /var/qmail/bin/qmail-remote /var/qmail/bin/qmail-remote.orig
cat > /var/qmail/bin/qmail-remote << __EOS___

#!/usr/local/bin/bash
DOMAIN="$MYDOMAINNAME"
DKREMOTE="/var/qmail/bin/qmail-remote.orig"
DKSIGN="/etc/domainkeys/\$DOMAIN/default"
tmp=`/usr/bin/mktemp -t dk.sign.XXXXXXXXXXXXXXXXXXX`
/bin/cat - >"\$tmp" ( /usr/local/bin/dktest -s "\$DKSIGN" -c nofws -h <"\$tmp" 2>/dev/null | /usr/bin/sed 's/; d=.*;/; d='"\$DOMAIN"';/' ; /usr/local/bin/dkimsign.pl --type=dkim --selector=default --method=relaxed <"\$tmp" | /usr/bin/tr -d '\r' ;/bin/cat "\$tmp" ) | "\$DKREMOTE" "\$@"
retval=\$?
/bin/rm "\$tmp"
exit \$retval

__EOS___



###
###
# http://jeremy.kister.net/howto/dk.html
###
###

echo "ADD DOMAIN AND EMAIL ADDRESS"
echo "****************************"
echo ""
echo "Enter domain"
read getDomain
echo "Enter password"
read getPassword
/usr/local/vpopmail/bin/vadddomain $getDomain $getPassword
echo ""
echo "Add email address to domain $getDomain"
echo "**************************************"
echo ""
echo "Enter email address"
read getEmailaddress
echo ""
echo "Enter Password for that email address"
read getEmailpassword
/usr/local/vpopmail/bin/vadduser $getEmailaddress $getEmailpassword


echo ""
echo "Adding DKIM to domain"
echo "Your domain"
read yourDomain

mkdir -p /etc/domainkeys/$yourDomain
cd /etc/domainkeys/$yourDomain
/usr/bin/openssl genrsa -out default 1024
/usr/bin/openssl rsa -in default -out rsa.public -pubout -outform PEM
chown -R qmailq /etc/domainkeys
chmod 0666 default
# grep -v ^- rsa.public | perl -e 'while(<>){chop;$l.=$_;}print "k=rsa; t=y; p=$l;\n";'
defaultresult=$(grep -v ^- rsa.public | perl -e 'while(<>){chop;$l.=$_;}print "k=rsa; t=y; p=$l;\n";')


echo "Enter the IP address of your server"
read mYServerIP
IFS="." read -a myarray <<< $mYServerIP
newIPstring="${myarray[0]}.${myarray[1]}.${myarray[2]}"

mkdir ~vpopmail/etc
echo "$newIPstring.:allow,RELAYCLIENT=\"\",DKSIGN=\"/etc/domainkeys/$yourDomain/default\",QMAILQUEUE=\"/var/qmail/bin/qmail-dk\",DKQUEUE=\"/var/qmail/bin/qmail-queue.orig\",DKREMOTE=\"/var/qmail/bin/qmail-remote.orig\"" > /usr/local/vpopmail/etc/tcp.smtp
echo '127.0.0.:allow,RELAYCLIENT="",DKSIGN="/etc/domainkeys/$yourDomain/default",QMAILQUEUE="/var/qmail/bin/qmail-dk",DKQUEUE="/var/qmail/bin/qmail-queue.orig",DKREMOTE="/var/qmail/bin/qmail-remote.orig"' >> /usr/local/vpopmail/etc/tcp.smtp
echo '192.168.0.:allow,RELAYCLIENT="",DKSIGN="/etc/domainkeys/$yourDomain/default",QMAILQUEUE="/var/qmail/bin/qmail-dk",DKQUEUE="/var/qmail/bin/qmail-queue.orig",DKREMOTE="/var/qmail/bin/qmail-remote.orig"' >> /usr/local/vpopmail/etc/tcp.smtp
echo '0.0.0.:allow,RELAYCLIENT="",DKSIGN="/etc/domainkeys/$yourDomain/default",QMAILQUEUE="/var/qmail/bin/qmail-dk",DKQUEUE="/var/qmail/bin/qmail-queue.orig",DKREMOTE="/var/qmail/bin/qmail-remote.orig"' >> /usr/local/vpopmail/etc/tcp.smtp
echo ':allow,DKVERIFY="BDEGIJKfh",QMAILQUEUE="/var/qmail/bin/qmail-dk",DKQUEUE="/var/qmail/bin/qmail-queue.orig",DKREMOTE="/var/qmail/bin/qmail-remote.orig"' >> /usr/local/vpopmail/etc/tcp.smtp
tcprules /usr/local/vpopmail/etc/tcp.smtp.cdb /usr/local/vpopmail/etc/tcp.smtp.tmp < /usr/local/vpopmail/etc/tcp.smtp


# echo "$newIPstring.:allow,RELAYCLIENT=\"\"" > /usr/local/vpopmail/etc/tcp.smtp
# echo '101.182.92.:allow,RELAYCLIENT=""' >> /usr/local/vpopmail/etc/tcp.smtp
# echo '127.0.0.:allow,RELAYCLIENT=""' >> /usr/local/vpopmail/etc/tcp.smtp
# echo '192.168.0.:allow,RELAYCLIENT=""' >> /usr/local/vpopmail/etc/tcp.smtp
# echo '0.0.0.:allow,RELAYCLIENT=""' >> /usr/local/vpopmail/etc/tcp.smtp
# echo ':allow' >> /usr/local/vpopmail/etc/tcp.smtp
# tcprules /usr/local/vpopmail/etc/tcp.smtp.cdb /usr/local/vpopmail/etc/tcp.smtp.tmp < /usr/local/vpopmail/etc/tcp.smtp
# 

echo ""
echo "Adding to your bind/named record"
echo "Enter email address for your domain key"
read domainkeyEmail
echo "Enter domain name"
echo "*****************"
echo "This will append to the file /usr/local/etc/namedb/YOURDOMAIN"
read  domainkeyDomain

cat <<EOF>> /usr/local/etc/namedb/$domainkeyDomain
; SPF Record for MX.
sumason.org.        IN      TXT     "v=spf1 a mx -all"

; DKIM policy record
_domainkey.$domainkeyDomain.          IN TXT "o=!;r=$domainkeyEmail"
default._domainkey.$domainkeyDomain.  IN TXT "k=rsa; t=y; p=$defaultresult"

;     o=~ the server signs some mail
;     o=- all mail is signed, but unsigned mail should be accepted
;     o=! all mail is signed, do not accept unsigned mail
;     t=y I’m still testing
;     v=DKIM1 we use DKIM version 1
;     k=rsa it is a RSA key
;     r=<x@xx> report problems to this email address
;     p=<public key> this is the generated public key
_dmarc.$domainkeyDomain. IN TXT "v=DMARC1; p=none; rua=mailto:$domainkeyEmail; ruf=mailto:$domainkeyEmail; sp=none; ri=86400"
_smtp._tcp.$domainkeyDomain.   86400 IN    SRV 10       60     25 $domainkeyDomain.
EOF






echo "Enter domain name for qmail start"
read qmailsDomainname
cat <<EOF> /usr/local/etc/rc.d/qmail.sh
if [ ! -f /var/qmail/rc ]; then
  echo "/var/qmail/rc missing"
        exit 0
fi

case "\$1" in
start)
export SMTPAUTH='!'
csh -cf '/var/qmail/rc start &'
/usr/bin/nohup /usr/local/bin/tcpserver -l0 -H -R 0 pop3 /var/qmail/bin/qmail-popup $qmailsDomainname /usr/local/vpopmail/bin/vchkpw /var/qmail/bin/qmail-pop3d Maildir&
/usr/bin/nohup /usr/local/bin/tcpserver -vHR -c 240 -l $qmailsDomainname -x /usr/local/vpopmail/etc/tcp.smtp.cdb -u 89 -g 89 0 587 /var/qmail/bin/qmail-smtpd $qmailsDomainname /usr/local/vpopmail/bin/vchkpw /usr/bin/true&

IP="0"                  # IP on which to listen
PORT="995"                      # TCP port number, 995 is standard
LOCAL="$qmailsDomainname"               # your local hostname
CHECKPW="/usr/local/vpopmail/bin/vchkpw"
                              

export CERTFILE="/var/qmail/control/servercert.pem"
export KEYFILE=""
export DHFILE=""

        /usr/bin/nohup /usr/local/bin/sslserver -e -vRH -l \$LOCAL \$IP \$PORT  qmail-popup \$LOCAL \$CHECKPW qmail-pop3d Maildir&
        ##tcprules /usr/local/vpopmail/etc/tcp.smtp.cdb /usr/local/vpopmail/etc/tcp.smtp.tmp < /usr/local/vpopmail/etc/tcp.smtp
        #qmailtcpserver: usage: tcpserver [ -1UXpPhHrRoOdDqQv ] [ -c limit ] [ -x rules.cdb ] [ -B banner ] [ -g gid ] [ -u uid ] [ -b backlog ] [ -l localname ] [ -t timeout ] host port program
        cmdtext="starting"
        ;;
stop)
        killall -m qmail
        killall -m tcpserver
        killall -m sslserver
        cmdtext="stopping"
        ;;
*)
        echo "Usage: \$0 {start|stop}"
        exit 1
        ;;
esac

echo "QMail \$cmdtext."
exit 0

EOF

chmod 755 /usr/local/etc/rc.d/qmail.sh


echo ""
echo "***********************************"
echo ""
echo "You need to change the settings in /usr/local/bin/dkimsign.pl for the domainkey being in /etc/domainkeys"
echo ""
