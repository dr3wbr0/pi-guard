#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "This script must run as root"
  exit
fi

echo "Welcome to the Pi-Guard installation script!"
echo
sleep 2
echo "Your public IP address is:" && echo $(ip a | grep eth0 -m 2 | egrep '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}' -o | grep -v 255)
echo
sleep 2
echo "Make sure you have already created a DNS entry with your registrar."
echo
sleep 2
read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
read -p "Enter username for new non-root user: " NEWUSR
read -sp "Enter new password for $NEWUSR: " PSSWD
echo
read -sp "Confirm password: " PSSWD2

# check if passwords match and if not ask again
while [ "$PSSWD" != "$PSSWD2" ];
do
    echo 
    echo "Please try again"
    read -sp "Password: " PSSWD
    echo
    read -sp "Confirm password: " PSSWD2
done

# Create new non-root user
echo
adduser --disabled-password --gecos "" $NEWUSR
usermod -aG sudo $NEWUSR
cp -r /root/.ssh /home/$NEWUSR
chown -R $NEWUSR:$NEWUSR /home/$NEWUSR/.ssh
echo "$NEWUSR:$PSSWD" | chpasswd
rm -fr /root/.ssh

# Grab IP details
ETH0CDR=$(ip a | grep eth0 -m 2 | egrep '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{2}' -o)
ROUTERS=$(ip route | grep default -m 1 | egrep '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}' -o)
ETH1CDR=$(ip a | grep eth1 -m 2 | egrep '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{2}' -o)

# Install new packages
apt update
apt install -y wireguard-tools certbot unattended-upgrades

# Configure ascii motd
sed -i '29 s/to %s/to Pi-Guard %s/' /etc/update-motd.d/00-header
chmod -x /etc/update-motd.d/10-help-text

echo '#!/bin/bash' > /etc/update-motd.d/01-update
echo -e "cat << 'EOF'
   ____  _        ____                     _ 
  |  _ \(_)      / ___|_   _  __ _ _ __ __| |
  | |_) | |_____| |  _| | | |/ _\` | '__/ _\` |
  |  __/| |_____| |_| | |_| | (_| | | | (_| |
  |_|   |_|      \____|\__,_|\__,_|_|  \__,_|
EOF
" >> /etc/update-motd.d/01-update
chmod +x /etc/update-motd.d/01-update


# Install Pi-hole
echo
echo "Note: It doesn't matter what upstream DNS servers you choose during the Pi-hole" && echo "configuration because they will be overwritted when we install unbound."
read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

curl -sSL https://install.pi-hole.net | bash
echo && echo "Pi-hole WebUI"
pihole -a -p
pihole -a -f
echo
# pihole -a -i all


# Install local DNS server
apt install -y unbound dhcpcd5

# Configure Unbound
echo "server:
    # If no logfile is specified, syslog is used
    # logfile: \"/var/log/unbound/unbound.log\"
    verbosity: 0

    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes

    # May be set to yes if you have IPv6 connectivity
    do-ip6: no

    # You want to leave this to no unless you have *native* IPv6. With 6to4 and
    # Terredo tunnels your web browser should favor IPv4 for the same reasons
    prefer-ip6: no

    # Use this only when you downloaded the list of primary root servers!
    # If you use the default dns-root-data package, unbound will find it automatically
    #root-hints: \"/var/lib/unbound/root.hints\"

    # Trust glue only if it is within the server's authority
    harden-glue: yes

    # Require DNSSEC data for trust-anchored zones, if such data is absent, the zone becomes BOGUS
    harden-dnssec-stripped: yes

    # Don't use Capitalization randomization as it known to cause DNSSEC issues sometimes
    # see https://discourse.pi-hole.net/t/unbound-stubby-or-dnscrypt-proxy/9378 for further details
    use-caps-for-id: no

    # Reduce EDNS reassembly buffer size.
    edns-buffer-size: 1232

    # Perform prefetching of close to expired message cache entries
    # This only applies to domains that have been frequently queried
    prefetch: yes

    # One thread should be sufficient, can be increased on beefy machines. In reality for most users running on small networks or on a single machine, it should be unnecessary to seek performance enhancement by increasing num-threads above 1.
    num-threads: 1

    # Ensure kernel buffer is large enough to not lose messages in traffic spikes
    so-rcvbuf: 1m

    # Ensure privacy of local IP ranges
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10" > /etc/unbound/unbound.conf.d/pi-hole.conf

# Configure dhcpcd5
echo "interface eth0
    static ip_address=$ETH0CDR
    static routers=$ROUTERS
    static domain_name_servers=127.0.0.1#5335
interface eth1
    static ip_address=$ETH1CDR" >> /etc/dhcpcd.conf

# Restart DNS services
# systemctl disable systemd-resolved.service
# systemctl stop systemd-resolved.service
echo "Reloading local DNS services..."
echo
sleep 2
systemctl disable unbound-resolvconf.service
systemctl stop unbound-resolvconf.service
sudo systemctl restart unbound.service
sudo systemctl restart dhcpcd.service

# Test domain name resolution
echo "Testing DNSSEC support..."
echo
sleep 2
dig @127.0.0.1 -p 5335 dns.google.com
echo
dig sigfail.verteiltesysteme.net @127.0.0.1 -p 5335
echo
dig sigok.verteiltesysteme.net @127.0.0.1 -p 5335
echo

# Change Upstream Pi-hole DNS
sed -i '4 s/=.*/=127\.0\.0\.1#5335/' /etc/pihole/setupVars.conf
sed -i '5 s/=.*/=/' /etc/pihole/setupVars.conf
pihole restartdns

# Configure Wireguard
echo
echo "Time to configure wireguard..."
sleep 2
cd /etc/wireguard
umask 077
wg genkey | tee server_private_key | wg pubkey > server_public_key

echo
read -p "Enter third octet for Wireguard private network: 10.100." OCTET  
read -p "Enter client private key: " PRIVKEY
PUBKEY=$(echo $PRIVKEY | wg pubkey)

echo "[Interface]
Address = 10.100.$OCTET.1/24
SaveConfig = true
PrivateKey = $(cat server_private_key)
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = $PUBKEY
AllowedIPs = 10.100.$OCTET.2/32" > /etc/wireguard/wg0.conf

umask 022

sudo sed -i '28 s/\#//' /etc/sysctl.conf
sudo sysctl -p
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0.service

echo
echo "Generating client configuration..." && echo
MYIP=$(ip a | grep eth0 -m 2 | egrep '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}' -o | grep -v 255)

echo "[Interface]
PrivateKey = $PRIVKEY
Address = 10.100.$OCTET.2/24
DNS = 10.100.$OCTET.1

[Peer]
PublicKey = $(cat server_public_key)
AllowedIPs = 0.0.0.0/0
Endpoint = $MYIP:51820
PersistentKeepalive = 25"
echo
echo "Copy the above config for Wireguard client config."
read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

# Install Let's Encrypt SSL certificate
echo
echo "Time to install the Let's Encrypt certificate..."
echo
sleep 2
systemctl stop lighttpd.service
cp /etc/lighttpd/external.conf /etc/lighttpd/external.conf.orig
certbot certonly --standalone
FQDN=$(grep -m 1 -v "#" /etc/hosts | cut -f2 -d ' ')
TLD=$(echo $FQDN | cut -d '.' -f2,3)
KEYDIR=$(find /etc/letsencrypt/live/ -name "*.$TLD")
ARCDIR=$(find /etc/letsencrypt/archive/ -name "*.$TLD")
CERTNM=$(echo $ARCDIR | cut -d '/' -f5)

cat $KEYDIR/privkey.pem \
$KEYDIR/cert.pem | \
tee $ARCDIR/combined.pem

cd $KEYDIR
ln -s ../../archive/$CERTNM/combined.pem combined.pem
chown www-data -R /etc/letsencrypt/live
echo "\$HTTP[\"host\"] == \"$CERTNM\" {
  # Ensure the Pi-hole Block Page knows that this is not a blocked domain
  setenv.add-environment = (\"fqdn\" => \"true\")

  # Enable the SSL engine with a LE cert, only for this specific host
  \$SERVER[\"socket\"] == \":443\" {
    ssl.engine = \"enable\"
    ssl.pemfile = \"/etc/letsencrypt/live/$CERTNM/combined.pem\"
    ssl.ca-file =  \"/etc/letsencrypt/live/$CERTNM/fullchain.pem\"
    ssl.honor-cipher-order = \"enable\"
    ssl.cipher-list = \"EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH\"
    ssl.use-sslv2 = \"disable\"
    ssl.use-sslv3 = \"disable\"       
  }

  # Redirect HTTP to HTTPS
  \$HTTP[\"scheme\"] == \"http\" {
    \$HTTP[\"host\"] =~ \".*\" {
      url.redirect = (\".*\" => \"https://%0\$0\")
    }
  }
}" > /etc/lighttpd/external.conf
cd
systemctl restart lighttpd.service

# Configure unattended-upgrades
echo
echo "Configuring automatic upgrades..."
echo
sleep 2
echo "APT::Periodic::Enable \"1\";
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
APT::Periodic::AutocleanInterval \"7\";" > /etc/apt/apt.conf.d/20auto-upgrades

sed -i '15 s/^\/\///' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i '83 s/^\/\///' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i '90 s/^\/\///' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i '94 s/^\/\///' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i '90 s/false/true/' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i '94 s/false/true/' /etc/apt/apt.conf.d/50unattended-upgrades

systemctl status apt-daily.timer
systemctl status apt-daily-upgrade.timer
ln -s /var/log/apt/history.log /home/$NEWUSR/upgrade.log

# Set permit root login "no"
sed -i '34 s/yes/no/' /etc/ssh/sshd_config

cat << "EOF"
  ____  _        ____                     _ 
 |  _ \(_)      / ___|_   _  __ _ _ __ __| |
 | |_) | |_____| |  _| | | |/ _` | '__/ _` |
 |  __/| |_____| |_| | |_| | (_| | | | (_| |
 |_|   |_|      \____|\__,_|\__,_|_|  \__,_|
                                           
EOF

sed -i '1 s/\/bin\/bash/\/usr\/sbin\/nologin/' /etc/passwd
echo "Root login has been disabled." && echo
read -p "Installation complete! Install updates and reboot now? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

screen -dmS shieldsup bash -c 'unattended-upgrade -d; reboot'

bash -c 'exit'
exit