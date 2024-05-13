curl -L https://big.oisd.nl/domainswild > oisd.list
curl -L https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate.txt > hagezi.list
curl -L https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | tail -n +29 | sed "s/^0.0.0.0 /*./g" > steve.list
