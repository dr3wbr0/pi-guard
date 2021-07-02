#!/bin/bash

echo
echo "Welcome to the Pi-Guard installation script!"
echo
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

# Install new packages
apt update
apt install -y wireguard-tools certbot unattended-upgrades screenfetch
wget -q https://bin.equinox.io/c/VdrWdbjqyF/cloudflared-stable-linux-amd64.deb
dpkg -i cloudflared-stable-linux-amd64.deb

# Configure screenfetch
sed -i '29 s/to %s/to Pi-Guard %s/' /etc/update-motd.d/00-header
chmod -x /etc/update-motd.d/10-help-text
echo '#!/bin/sh
/usr/bin/screenfetch' > /etc/update-motd.d/01-update
chmod +x /etc/update-motd.d/01-update
echo '#!/bin/bash' > /etc/update-motd.d/02-update
echo -e "

cat << 'EOF'
  ____  _        ____                     _ 
 |  _ \(_)      / ___|_   _  __ _ _ __ __| |
 | |_) | |_____| |  _| | | |/ _\` | '__/ _\` |
 |  __/| |_____| |_| | |_| | (_| | | | (_| |
 |_|   |_|      \____|\__,_|\__,_|_|  \__,_|
                                           
EOF
" >> /etc/update-motd.d/02-update
chmod +x /etc/update-motd.d/02-update

# Install Cloudflared for DNS over HTTPS
cloudflared -v
mkdir /etc/cloudflared/
echo "proxy-dns: true
proxy-dns-port: 5053
proxy-dns-upstream:
  - https://1.1.1.1/dns-query
  - https://1.0.0.1/dns-query" > /etc/cloudflared/config.yml
cloudflared service install --legacy
systemctl start cloudflared

dig @127.0.0.1 -p 5053 google.com
echo

# Install Pi-hole
echo "Copy this value for the custom DNS address: " && echo "127.0.0.1#5053"
read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

curl -sSL https://install.pi-hole.net | bash
echo && echo "Pi-hole WebUI"
pihole -a -p
pihole -a -f
pihole -a -i all

# Configure Wireguard
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
systemctl stop lighttpd.service
cp /etc/lighttpd/external.conf /etc/lighttpd/external.conf.orig
certbot certonly --standalone
FQDN=$(hostname).$(dnsdomainname)

cat /etc/letsencrypt/live/$FQDN/privkey.pem \
/etc/letsencrypt/live/$FQDN/cert.pem | \
tee /etc/letsencrypt/live/$FQDN/combined.pem

chown www-data -R /etc/letsencrypt/live
echo "\$HTTP[\"host\"] == \"$FQDN\" {
  # Ensure the Pi-hole Block Page knows that this is not a blocked domain
  setenv.add-environment = (\"fqdn\" => \"true\")

  # Enable the SSL engine with a LE cert, only for this specific host
  \$SERVER[\"socket\"] == \":443\" {
    ssl.engine = \"enable\"
    ssl.pemfile = \"/etc/letsencrypt/live/$FQDN/combined.pem\"
    ssl.ca-file =  \"/etc/letsencrypt/live/$FQDN/fullchain.pem\"
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

systemctl restart lighttpd.service

# Configure unattended-upgrades
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
# ln -s /var/log/unattended-upgrades /home/$NEWUSR/unattended-upgrades
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

read -p "Install complete. Run unattended-upgrades now? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

rm /root/cloudflared-stable-linux-amd64.deb

unattended-upgrade -d

