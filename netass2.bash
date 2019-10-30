#!/bin/bash

function AsciiPrint() {
	echo ""
	echo "      __     _     _           ____   "
	echo "   /\ \ \___| |_  / \  ___ ___|___ \  "
	echo "  /  \/ / _ \ __|/ O \/ __/ __| __) | "
	echo " / /\  /  __/ |_/  _  \__ \__ \/ __/  "
	echo " \_\ \/ \___|\__\_/ \_/___/___/_____\ "
	echo "     Network Assessment Assistance    "
	echo ""
}

function BannerPrint() {
	echo ' ------------------------------------------ '
	echo ' | NAME  : Network Assessment Assistance  | '
	echo ' | ALIAS : NetAss2                        | '
	echo ' | TYPE  : VA Framework                   | '
	echo ' | VERS  : 0.1-RC                         | '
	echo ' | LICEN : GPL v3                         | '
	echo ' | LINK  : github.com/zerobyte-id/NetAss2 | '
	echo ' ------------------------------------------ '
}

if [[ $(whoami) != "root" ]]; then
	echo " ERROR: Please run as root"
	exit
elif [[ -z $(command -v nmap) ]]; then
	echo " ERROR: \"nmap\" tool not found"
	echo " HINT: Please install nmap first"
	exit
elif [[ -z $(command -v zmap) ]]; then
	echo " ERROR: \"zmap\" tool not found"
	echo " HINT: Please install zmap first"
	exit
elif [[ ! -z $(cat /etc/zmap/zmap.conf | grep ^"blacklist-file") ]]; then
	echo " ERROR: Please turn off zmap \"blacklist\""
	echo " HINT: Remove \"blacklist-file\" in /etc/zmap/zmap.conf"
	exit
fi

if [[ -d /opt ]]; then
	if [[ ! -d /opt/NetAss2 ]]; then
		mkdir /opt/NetAss2
	fi
fi
if [[ -d /opt ]]; then
	if [[ ! -d /opt/NetAss2/project ]]; then
		mkdir /opt/NetAss2/project
	fi
fi

while true
do
	echo ""
	BannerPrint
	echo ""
	echo -ne " Enter a project name: "
	read PROJECT
	echo ""
	if [[ -d /opt/NetAss2/project/${PROJECT} ]]; then
		echo " ERROR: Project already exist"
	else
		mkdir /opt/NetAss2/project/${PROJECT}
		break
	fi
done

echo " --------------------------------------------------"

while true
do

AsciiPrint
echo " [1]. HOST DISCOVERY"
echo " [2]. PORT SCAN ON SINGLE HOST"
echo " [3]. MASSIVE PORT SCAN VIA DISCOVERED HOSTS"
echo " [4]. MASSIVE PORT SCAN VIA LIST ON FILE"
echo " [5]. SINGLE PORT QUICK SCAN VIA NETWORK BLOCK"
echo " [6]. MULTIPLE PORT QUICK SCAN VIA NETWORK BLOCK"
echo " [!]. SHOW REPORTS"
echo " [0]. EXIT"
echo ""
echo -ne " INPUT: "
read MENU
echo ""

if [[ ${MENU} == 1 ]]; then
	echo " ----------------[ HOST DISCOVERY ]----------------"
	echo ""
	if [[ ! -z $(ip a | grep 'inet ' | grep -v ' lo'$ | awk '{print $2}') ]]; then
		echo " NOTE: Your network block reminder"
		for NETBLOCK in $(ip a | grep 'inet ' | grep -v ' lo'$ | awk '{print $2}')
		do
			echo "  + ${NETBLOCK}"
		done
		echo ""
	fi
	echo " NOTE: Enter the network block that you want to scan"
	echo " NOTE: Example: 192.168.1.0/24"
	echo -ne " INPUT: "
	read NETWORK
	if [[ -z ${NETWORK} ]]; then
		echo " ERROR: Please input network block"
	elif [[ -z $(echo ${NETWORK} | grep -E "^([0-9]{1,3}[\.]){3}[0-9]{1,3}[/][0-9]{1,2}$") ]]; then
		echo " ERROR: Please input valid network block"
	else
		if [[ -f host-discover.na2out ]]; then
			rm host-discover.na2out
		fi
		echo " INFO: Nmap run..."
		echo " INFO: Discovering host..."
		nmap -sn ${NETWORK} -o nmap-host.na2out &> /dev/null
		if [[ $(cat nmap-host.na2out | grep -i 'Nmap scan report for' | awk '{print $5}' | wc -l) -ge 1 ]]; then
			cat nmap-host.na2out | grep -i 'Nmap scan report for' | awk '{print $5}' >> /opt/NetAss2/project/${PROJECT}/host-alive.csv
			if [[ -f nmap-host.na2out ]]; then
				rm nmap-host.na2out
			fi
			cat /opt/NetAss2/project/${PROJECT}/host-alive.csv | sort -V | uniq >> hostdicovery.na2tmp
			rm /opt/NetAss2/project/${PROJECT}/host-alive.csv
			mv hostdicovery.na2tmp /opt/NetAss2/project/${PROJECT}/host-alive.csv
			echo " Host" > hostdsc.na2tmp
			echo " ------------" >> hostdsc.na2tmp
			cat /opt/NetAss2/project/${PROJECT}/host-alive.csv | sed "s/^/ /g" >> hostdsc.na2tmp
			echo ""
			cat hostdsc.na2tmp
			rm hostdsc.na2tmp
		fi
	fi

elif [[ ${MENU} == 2 ]]; then
	echo " -----------[ PORT SCAN ON SINGLE HOST ]-----------"
	echo ""
	if [[ -f /opt/NetAss2/project/${PROJECT}/host-alive.csv ]]; then
		if [[ $(cat /opt/NetAss2/project/${PROJECT}/host-alive.csv | wc -l) -ge 1 ]]; then
			echo " INFO: Discovered host"
			for IP in $(cat /opt/NetAss2/project/${PROJECT}/host-alive.csv)
			do
				echo "  + ${IP}"
			done
			echo ""
		fi
	fi
	echo " NOTE: Enter the specific host that you want to scan"
	echo " NOTE: Example: 192.168.1.100"
	echo -ne " INPUT: "
	read IPADDR
	if [[ -z $(echo ${IPADDR} | grep -E "^([0-9]{1,3}[\.]){3}[0-9]{1,3}$") ]]; then
		echo " ERROR: Please input valid network block"
	else
		if [[ -f port-scan.na2out ]]; then
			rm port-scan.na2out
		fi
		echo " INFO: Nmap run..."
		echo " INFO: Discovering port on ${IPADDR}..."
		nmap -p- -sT -sV --version-intensity 5 -T5 ${IPADDR} -oN port-scan.na2out -v &> /dev/null
		cat port-scan.na2out | grep ^[0-9] | grep '[0-9][/]' | sed 's/;/,/g' | awk '{for(i=4;i<=NF;i++) printf $i" ";print ";"$1";"$3}' | sed 's/ ;/;/g' | awk -F ';' '{print $2";"$3";"$1}' | sed "s/^/${IPADDR};/g" >> /opt/NetAss2/project/${PROJECT}/port-open.csv
		if [[ -f na2-output.tmp ]]; then
			rm na2-output.tmp
		fi
		cat /opt/NetAss2/project/${PROJECT}/port-open.csv | sort -V | uniq >> na2-output.tmp
		rm /opt/NetAss2/project/${PROJECT}/port-open.csv
		mv na2-output.tmp /opt/NetAss2/project/${PROJECT}/port-open.csv
		if [[ $(cat /opt/NetAss2/project/${PROJECT}/port-open.csv | grep "${IPADDR}" | wc -l) -lt 1 ]]; then
			echo " INFO: Port not found"
		else
			echo "IP Addr;Port;Service;Vendor" > na2out.csv
			echo "-------;----;-------;------" >> na2out.csv
			cat /opt/NetAss2/project/${PROJECT}/port-open.csv | grep "${IPADDR}" >> na2out.csv
			sed -i "s/^/ /g" na2out.csv
			echo ""
			cat na2out.csv | column -t -s';'
			rm na2out.csv
		fi
		if [[ -f port-scan.na2out ]]; then
			rm port-scan.na2out
		fi
	fi

elif [[ ${MENU} == 3 ]]; then
	echo " ----[ MASSIVE PORT SCAN VIA DISCOVERED HOSTS ]----"
	echo ""
	if [[ ! -f /opt/NetAss2/project/${PROJECT}/host-alive.csv ]]; then
		echo " ERROR: Please run host discovery first"
	elif [[ $(cat /opt/NetAss2/project/${PROJECT}/host-alive.csv | wc -l) -eq 0 ]]; then
		echo " ERROR: No discovered host"
	else
		for IPADDR in $(cat /opt/NetAss2/project/${PROJECT}/host-alive.csv)
		do
			if [[ -f port-scan.na2out ]]; then
				rm port-scan.na2out
			fi
			echo " INFO: Nmap run..."
			echo " INFO: Discovering port on ${IPADDR}..."
			nmap -p- -sT -sV --version-intensity 5 -T5 ${IPADDR} -oN port-scan.na2out -v &> /dev/null
			cat port-scan.na2out | grep ^[0-9] | grep '[0-9][/]' | sed 's/;/,/g' | awk '{for(i=4;i<=NF;i++) printf $i" ";print ";"$1";"$3}' | sed 's/ ;/;/g' | awk -F ';' '{print $2";"$3";"$1}' | sed "s/^/${IPADDR};/g" >> /opt/NetAss2/project/${PROJECT}/port-open.csv
			if [[ -f na2-output.tmp ]]; then
				rm na2-output.tmp
			fi
			if [[ -f port-scan.na2out ]]; then
				rm port-scan.na2out
			fi
			cat /opt/NetAss2/project/${PROJECT}/port-open.csv | sort -V | uniq >> na2-output.tmp
			rm /opt/NetAss2/project/${PROJECT}/port-open.csv
			mv na2-output.tmp /opt/NetAss2/project/${PROJECT}/port-open.csv
		done
		if [[ $(cat /opt/NetAss2/project/${PROJECT}/port-open.csv | wc -l) -lt 1 ]]; then
			echo " INFO: Port not found"
		else
			echo "IP Addr;Port;Service;Vendor" > na2out.csv
			echo "-------;----;-------;------" >> na2out.csv
			cat /opt/NetAss2/project/${PROJECT}/port-open.csv >> na2out.csv
			sed -i "s/^/ /g" na2out.csv
			echo ""
			cat na2out.csv | column -t -s';'
			rm na2out.csv
		fi
	fi

elif [[ ${MENU} == 4 ]]; then
	echo " ------[ MASSIVE PORT SCAN VIA LIST ON FILE ]------"
	echo ""
	echo " INFO: Your current path is $(pwd)"
	echo ""
	echo " NOTE: Input filename"
	echo " NOTE: Example: /path-to/ip-list.txt"
	echo -ne " INPUT: "
	read FILENAME 
	if [[ -z ${FILENAME} ]]; then
		echo " ERROR: Please input filename correctly"
	elif [[ -f ${FILENAME} ]]; then
		if [[ -z $(cat ${FILENAME} | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}") ]]; then
			echo " ERROR: No valid IP address on ${FILENAME}"
		else
			for IPADDR in $(cat ${FILENAME} | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
			do
				if [[ -f port-scan.na2out ]]; then
					rm port-scan.na2out
				fi
				echo " INFO: Nmap run..."
				echo " INFO: Discovering port on ${IPADDR}..."
				nmap -p- -sT -sV --version-intensity 5 -T5 ${IPADDR} -oN port-scan.na2out -v &> /dev/null
				cat port-scan.na2out | grep ^[0-9] | grep '[0-9][/]' | sed 's/;/,/g' | awk '{for(i=4;i<=NF;i++) printf $i" ";print ";"$1";"$3}' | sed 's/ ;/;/g' | awk -F ';' '{print $2";"$3";"$1}' | sed "s/^/${IPADDR};/g" >> /opt/NetAss2/project/${PROJECT}/port-open.csv
				if [[ -f na2-output.tmp ]]; then
					rm na2-output.tmp
				fi
				if [[ -f port-scan.na2out ]]; then
					rm port-scan.na2out
				fi
				cat /opt/NetAss2/project/${PROJECT}/port-open.csv | sort -V | uniq >> na2-output.tmp
				rm /opt/NetAss2/project/${PROJECT}/port-open.csv
				mv na2-output.tmp /opt/NetAss2/project/${PROJECT}/port-open.csv
			done
			if [[ $(cat /opt/NetAss2/project/${PROJECT}/port-open.csv | wc -l) -lt 1 ]]; then
				echo " INFO: Port not found"
			else
				echo "IP Addr;Port;Service;Vendor" > na2out.csv
				echo "-------;----;-------;------" >> na2out.csv
				cat /opt/NetAss2/project/${PROJECT}/port-open.csv >> na2out.csv
				sed -i "s/^/ /g" na2out.csv
				echo ""
				cat na2out.csv | column -t -s';'
				rm na2out.csv
			fi
		fi
	else
		echo " ERROR: ${FILENAME} not found"
	fi

elif [[ ${MENU} == 5 ]]; then
	echo "----[ SINGLE PORT QUICKSCAN VIA NETWORK BLOCK ]----"
	echo ""
	echo " NOTE: Enter the single port that you want to scan"
	echo " NOTE: Example: 80"
	echo -ne " INPUT: "
	read PORT
	if [[ -z ${PORT} ]]; then
		echo " ERROR: Please input single port"
	elif ! [[ ${PORT} =~ ^[0-9]+$ ]] ; then
		echo " ERROR: Please enter a valid port"
	elif [[ ${PORT} -lt 1 ]] && [[ ${PORT} -gt 65535 ]]; then
		echo " ERROR: Please enter a valid port"
	else
		if [[ ! -z $(ip a | grep 'inet ' | grep -v ' lo'$ | awk '{print $2}') ]]; then
			echo " NOTE: Your network block reminder"
			for NETBLOCK in $(ip a | grep 'inet ' | grep -v ' lo'$ | awk '{print $2}')
			do
				echo "  + ${NETBLOCK}"
			done
			echo ""
		fi
		echo " NOTE: Enter the network block that you want to scan"
		echo " NOTE: Example: 192.168.1.0/24"
		echo -ne " INPUT: "
		read NETWORK
		if [[ -z ${NETWORK} ]]; then
			echo " ERROR: Please input network block"
		elif [[ -z $(echo ${NETWORK} | grep -E "^([0-9]{1,3}[\.]){3}[0-9]{1,3}[/][0-9]{1,2}$") ]]; then
			echo " ERROR: Please input valid network block"
		else
			if [[ -f zmap-result.na2out ]]; then
				rm zmap-result.na2out
			fi
			if [[ $(ip a | grep 'inet ' | grep -v ' lo' | awk '{print $2}' | wc -l) -gt 1 ]]; then
				echo " WARNING: Your PC using multiple interface"
				ip a | grep 'inet ' | grep -v ' lo' | awk '{print "  + "$NF" ("$2")"}'
				echo " INFO: Please enter your interface (example: eth0)"
				echo -ne " INPUT: "
				read IFACE
				if [[ -z $(ip a | grep 'inet ' | grep -v ' lo' | awk '{print $NF}' | grep ^"${IFACE}"$) ]]; then
					echo " ERROR: Please input your iface correctly"
				else
					echo " INFO: Single port quickscan running..."
					zmap -p ${PORT} ${NETWORK} -i ${IFACE} -o zmap-result.na2out &> /dev/null
				fi
			else
				zmap -p ${PORT} ${NETWORK} -o zmap-result.na2out &> /dev/null
			fi
			cat zmap-result.na2out | sed "s/$/;${PORT}/g" >> /opt/NetAss2/project/${PROJECT}/quickscan-${PORT}.csv
			rm zmap-result.na2out
			cat /opt/NetAss2/project/${PROJECT}/quickscan-${PORT}.csv | sort -V | uniq >> na2-qsport.tmp
			rm /opt/NetAss2/project/${PROJECT}/quickscan-${PORT}.csv
			mv na2-qsport.tmp /opt/NetAss2/project/${PROJECT}/quickscan-${PORT}.csv
			echo "IP Addr;Port" > qsscanshow.tmp
			echo "-------;----" >> qsscanshow.tmp
			cat /opt/NetAss2/project/${PROJECT}/quickscan-${PORT}.csv >> qsscanshow.tmp
			sed -i "s/^/ /g" qsscanshow.tmp
			echo ""
			cat qsscanshow.tmp | column -t -s';'
			rm qsscanshow.tmp
		fi
	fi

elif [[ ${MENU} == '6' ]]; then
	echo "----[ MULTI PORT QUICK SCAN VIA NETWORK BLOCK ]----"
	echo ""
	if [[ $(ip a | grep 'inet ' | grep -v ' lo' | awk '{print $2}' | wc -l) -gt 1 ]]; then
		echo " WARNING: Your PC using multiple interface"
		ip a | grep 'inet ' | grep -v ' lo' | awk '{print "  + "$NF" ("$2")"}'
		echo " INFO: Please enter your interface (example: eth0)"
		echo -ne " INPUT: "
		read IFACE
		if [[ -z $(ip a | grep 'inet ' | grep -v ' lo' | awk '{print $NF}' | grep ^"${IFACE}"$) ]]; then
			echo " ERROR: Please input your iface correctly"
			IFACE="false"
		else
			IFACE=${IFACE}
		fi
	fi
	if [[ ${IFACE} == "false" ]]; then
		echo -ne ""
	else
		if [[ ! -z $(ip a | grep 'inet ' | grep -v ' lo'$ | awk '{print $2}') ]]; then
			echo " NOTE: Your network block reminder"
			for NETBLOCK in $(ip a | grep 'inet ' | grep -v ' lo'$ | awk '{print $2}')
			do
				echo "  + ${NETBLOCK}"
			done
			echo ""
		fi
		echo " NOTE: Enter the network block that you want to scan"
		echo " NOTE: Example: 192.168.1.0/24"
		echo -ne " INPUT: "
		read NETWORK
		if [[ -z ${NETWORK} ]]; then
			echo " ERROR: Please input network block"
		elif [[ -z $(echo ${NETWORK} | grep -E "^([0-9]{1,3}[\.]){3}[0-9]{1,3}[/][0-9]{1,2}$") ]]; then
			echo " ERROR: Please input valid network block"
		else
			echo " INFO: Input multiple port"
			echo " NOTE: Example: 22,80,443"
			echo -ne " INPUT: "
			read PORTS
			for PORT in $(echo "${PORTS}" | sed 's/,/\n/g')
			do
				if [[ -z ${PORT} ]]; then
					echo " ERROR: ${PORT} is invalid port"
				elif ! [[ ${PORT} =~ ^[0-9]+$ ]] ; then
					echo " ERROR: ${PORT} is invalid port"
				elif [[ ${PORT} -lt 1 ]] && [[ ${PORT} -gt 65535 ]]; then
					echo " ERROR: ${PORT} is invalid port"
				else
					if [[ -f zmap-result.na2out ]]; then
						rm zmap-result.na2out
					fi
					if [[ ! -z ${IFACE} ]]; then
						echo " INFO: Scanning port ${PORT} on ${NETWORK}..."
						zmap -p ${PORT} ${NETWORK} -i ${IFACE} -o zmap-result.na2out &> /dev/null
					else
						echo " INFO: Scanning port ${PORT} on ${NETWORK}..."
						zmap -p ${PORT} ${NETWORK} -o zmap-result.na2out &> /dev/null
					fi
					cat zmap-result.na2out | sed "s/$/;${PORT}/g" >> /opt/NetAss2/project/${PROJECT}/multiple-quickscan.csv
					rm zmap-result.na2out
					cat /opt/NetAss2/project/${PROJECT}/multiple-quickscan.csv | sort -V | uniq >> na2-qsport.tmp
					rm /opt/NetAss2/project/${PROJECT}/multiple-quickscan.csv
					mv na2-qsport.tmp /opt/NetAss2/project/${PROJECT}/multiple-quickscan.csv
				fi
			done
			echo "IP Addr;Port" > qsscanshow.tmp
			echo "-------;----" >> qsscanshow.tmp
			cat /opt/NetAss2/project/${PROJECT}/multiple-quickscan.csv >> qsscanshow.tmp
			sed -i "s/^/ /g" qsscanshow.tmp
			echo ""
			cat qsscanshow.tmp | column -t -s';'
			rm qsscanshow.tmp
		fi
	fi

elif [[ ${MENU} == '!' ]]; then
	echo "--------------[ NetAss2 - REPORTING ]--------------"
	echo ""
	if [[ $(ls /opt/NetAss2/project/${PROJECT}/ | wc -l) == 0 ]]; then
		echo " ERROR: No reporting data"
	else
		echo " INFO: Existing reports"
		for DATA in $(ls /opt/NetAss2/project/${PROJECT}/)
		do
			echo "  + ${DATA}"
		done
		echo ""
		echo -ne " INPUT: "
		read FILE
		echo ""
		if [[ -z ${FILE} ]]; then
			echo " ERROR: File cannot empty"
		elif [[ ! -f /opt/NetAss2/project/${PROJECT}/${FILE} ]]; then
			echo " ERROR: File not found"
		elif [[ $(cat /opt/NetAss2/project/${PROJECT}/${FILE} | wc -l) == 0 ]]; then
			echo " ERROR: No data for this report"
		else
			if [[ ${FILE} =~ ^"host-alive" ]]; then
				echo " HOST-ALIVE" > hostdsc.na2tmp
				echo " ------------" >> hostdsc.na2tmp
				cat /opt/NetAss2/project/${PROJECT}/${FILE} | sed "s/^/ /g" >> hostdsc.na2tmp
				cat hostdsc.na2tmp
				rm hostdsc.na2tmp
			elif [[ ${FILE} =~ ^"port-open" ]]; then
				echo "IP Addr;Port;Service;Vendor" > na2out.csv
				echo "-------;----;-------;------" >> na2out.csv
				cat /opt/NetAss2/project/${PROJECT}/${FILE} >> na2out.csv
				sed -i "s/^/ /g" na2out.csv
				cat na2out.csv | column -t -s';'
				rm na2out.csv
			elif [[ ${FILE} =~ ^"quickscan-" ]]; then
				echo "IP Addr;Port" > qsscanshow.tmp
				echo "-------;----" >> qsscanshow.tmp
				cat /opt/NetAss2/project/${PROJECT}/${FILE} >> qsscanshow.tmp
				sed -i "s/^/ /g" qsscanshow.tmp
				cat qsscanshow.tmp | column -t -s';'
				rm qsscanshow.tmp
			elif [[ ${FILE} =~ ^"multiple-" ]]; then
				echo "IP Addr;Port" > qsscanshow.tmp
				echo "-------;----" >> qsscanshow.tmp
				cat /opt/NetAss2/project/${PROJECT}/${FILE} >> qsscanshow.tmp
				sed -i "s/^/ /g" qsscanshow.tmp
				cat qsscanshow.tmp | column -t -s';'
				rm qsscanshow.tmp
			else
				echo " ERROR: Something wrong (RPT error)"
			fi
		fi
	fi

elif [[ ${MENU} == '0' ]]; then
	echo " INFO: Good bye~"
	echo ""
	exit

else
	echo " ERROR: Please select one menu correctly"
fi

echo ""
echo " --------------------------------------------------"

done
