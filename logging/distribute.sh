#!/bin/sh
printf "Enter network ip address minus the last octet (i.e. 192.168.1.): "
read -r ip
printf "Enter smallest number of last ip octet: "
read -r low
printf "Enter universal username: "
read -r user
printf "Enter universal password: "
read -r pass
printf "Elasticsearch ip: "
read -r el_ip
printf "Kibana ip: "
read -r kib_ip
printf "Fingerprint: "
read -r finger
printf "Elastic Password: "
read -r elastic_pass

while [ $low -lt 256 ]; do
  scp -o ConnectTimeout=5 linux_agent.sh "$user@$ip$low":~
  ssh -o ConnectTimeout=5 "$user@$ip$low" "sudo sh linux_agent.sh" <<EOF
$pass
$el_ip
$kib_ip
$finger
$elastic_pass
EOF
  low=$(($low+1))
done
