#!/bin/bash

if [[ $(whoami) != "root" ]]; then
	echo " ERROR: Please run as root"
fi

apt-get install nmap zmap -y

if [[ -z $(command -v nmap) ]]; then
	echo " ERROR: Please install \"nmap\" first"
	exit
elif [[ -z $(command -v zmap) ]]; then
	echo " ERROR: Please install \"zmap\" first"
	exit
fi

cp netass2.bash /usr/bin/netass2
chmod +x /usr/bin/netass2

echo ' DONE!'
echo ''
echo ' RUN:'
echo ' # netass2'