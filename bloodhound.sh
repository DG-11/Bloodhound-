#!/usr/bin/env bash
#Bloodhound is a packet sniffing script that allows pcap files be analyzed and separated into directories and logs for the Cyber security professional to view easily.

if zenity --question --text="Bloodhound Sniffing... \n analyze a pcap? "
then

#The line below this is how zenity allows users to visually pick a pcap file (graphically)
pcapName=$(zenity --file-selection --title="Select the pcap file you want to analyze." --file-filter="*.pcap")


#able to read pcap files. 

#Make an all purpose directory
mkdir Bloodhound

#Let's start our functionality

mkdir ./Bloodhound/Logins
#Search for Login Instances, Output instances to /Login directory

echo 1 > "/proc/sys/net/core/bpf_jit_enable"

echo -ne '\e[1;35mProgress ####                      (20%)\r'

tshark -r $pcapName | grep --color=always -i -E 'auth|denied|login|user|usr|SMTP|HTTP|success|psswd|pass|pw|logon|key|cipher|sum|token|pin|code|fail|correct|restrict' > ./Bloodhound/Logins/possible_logins.txt
tshark -Q -z credentials -r $pcapName > ./Bloodhound/Logins/credentials.txt

#Search for IP instances, show basic IP statistics, mkdir IP_Info, outpout files to IP_Info

mkdir ./Bloodhound/IP_Info

echo -ne '\e[1;35mProgress ########                  (40%)\r'

#Grep for ALL IP's (Source and Destination)
tshark -Q -r $pcapName -T fields -e ip.src -e ip.dst | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort | uniq -c | sort -n -r > ./Bloodhound/IP_Info/all_addresses.txt

#Grep for ALL Source IP Addresses
tshark -Q -r $pcapName -T fields -e ip.src | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort | uniq -c | sort -n -r > ./Bloodhound/IP_Info/source_addresses.txt

#Grep for All Destination IP Addresses
tshark -Q -r $pcapName -T fields -e ip.dst | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort | uniq -c | sort -n -r > ./Bloodhound/IP_Info/destination_addresses.txt


# A search for SMTP Auth only.(filter)
tshark   -r /home/kali/Downloads/evidence02.pcap -Y  "smtp.response.code " | sort | uniq -c | sort -n -r > ./Bloodhound/SMTP/SMTP_Items.txt   
#(-T fields -e "____")

mkdir ./Bloodhound/SMTP

#SQL Injection detection.
#tshark -r /home/kali/Downloads/"SQL Injection pcap".pcap -Y "http" |sort | uniq -c | sort -n -r > ./Bloodhound/SQL/SQL_Items.txt

#mkdir ./Bloodhound/SQL

#TCP stream detection
tshark -r /home/kali/Downloads/"SQL Injection pcap.pcap" -Y "tcp.stream eq 1" |sort | uniq -c | sort -n -r > ./Bloodhound/TCP/TCPSTREAM_Items.txt

mkdir ./Bloodhound/TCP

#Search for Objects within the Pcap, make an Objects directory, dump the files /Objects
mkdir ./Bloodhound/Objects

echo -ne '\e[1;35mProgress ############              (60%)\r'

The tshark commands below search for various objects to export from the user selected pcap
tshark -Q -r $pcapName --export-objects imf,./Bloodhound/Objects
tshark -Q -r $pcapName --export-objects dicom,./Bloodhound/Objects
tshark -Q -r $pcapName --export-objects smb,./Bloodhound/Objects
tshark -Q -r $pcapName --export-objects tftp,./Bloodhound/Objects
tshark -Q -r $pcapName --export-objects http,./Bloodhound/Objects





#Search for ALL instances of GET/POST/HEAD requests in the pcap, make directory for HTTP_Requests

mkdir ./Bloodhound/HTTP_Requests

echo -ne '\e[1;35mProgress #################         (80%)\r'

tshark -Vr $pcapName | grep --color=always -Eo '(GET|POST|HEAD) .* HTTP/1.[01]|Host: .*' | sort | uniq -c | sort -n > ./Bloodhound/HTTP_Requests/http_requests.txt

#Search for ALL instances of protocols (tcp,smtp,etc.) and make a directory to dump the file into
mkdir ./Bloodhound/Protocols

tshark -r $pcapName -T fields -e frame.protocols | sort | uniq -c | sort -n -r > ./Bloodhound/Protocols/protocols.txt


# Deleted the two email text files that would have been there

#Test to see if the created files are empty (have zero bytes) with test -s
test ! -s "./Bloodhound/HTTP_Requests/http_requests.txt" && rm -f "./Bloodhound/HTTP_Requests/http_requests.txt"
test ! -s "./Bloodhound/IP_Info/all_addresses.txt" && rm -f "./Bloodhound/IP_Info/all_addresses.txt"
test ! -s "./Bloodhound/IP_Info/destination_addresses.txt" && rm -f "./Bloodhound/IP_Info/destination_addresses.txt"
test ! -s "./Bloodhound/IP_Info/source_addresses.txt" && rm -f "./Bloodhound/IP_Info/source_addresses.txt"
test ! -s "./Bloodhound/Logins/credentials.txt" && rm -f "./Bloodhound/Logins/credentials.txt"
test ! -s "./Bloodhound/Logins/possible_logins.txt" && rm -f "./Bloodhound/Logins/possible_logins.txt"
test ! -s "./Bloodhound/Protocols/protocols.txt" && rm -f "./Bloodhound/Protocols/protocols.txt"


#Test whether the ./Bloodhound/Objects directory has any files. Delete if empty.

objectsDirSize=$(ls ./Bloodhound/Objects | wc -l)

if [ ! $objectsDirSize -gt 0 ]

then
	rm -rf ./Bloodhound/Objects

fi

echo -ne '\e[1;35mProgress #######################   (100%)\r'
echo -ne '\e[0;37m\n'

sleep 0.5

tree -s ./

#The zenity command below informs the user when the Bloodhound pcap scan is complete
zenity --info --text="Pcap scan complete. All output is in the 'Bloodhound' directory."

#The below fi statement marks the end of the original if-then statement
fi

