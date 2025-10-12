mkdir -p ./blocklists
curl -L https://big.oisd.nl/domainswild > ./blocklists/oisd.list
curl -L https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate.txt > ./blocklists/hagezi.list
curl -L https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | tail -n +29 | sed "s/^0.0.0.0 /*./g" > ./blocklists/steve.list
