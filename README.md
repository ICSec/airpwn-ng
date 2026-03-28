# Concept
airpwn-ng is a framework for 802.11 (wireless) packet injection.  It sniffs for wireless packets and if the data matches a specified trigger, custom content is injected.  From the perspective of the wireless client, airpwn-ng is the server.

airpwn-ng is based on the concepts laid out in [Airpwn](http://airpwn.sourceforge.net/Airpwn.html).

## How does this work?
* http://airpwn.sourceforge.net/Documentation.html
* https://github.com/ICSec/dc25

## Requirements
* [Aircrack-NG](https://www.aircrack-ng.org/install.html)
* [Scapy](https://github.com/secdev/scapy)

## Setup
airpwn-ng is designed to run installed via pip or decompressed as a module
```
python3 -m pip install RESOURCEs/airpwn-ng-*.tar.gz

## or

tar zxf RESOURCEs/airpwn-ng*
mv airpwn-ng-*/airpwn_ng .
```

## Example usage
The examples below are based on 1 or 2 NIC concepts.  While you can sniff and inject using just 1 NIC perhaps a situation arises to where injection using Managed mode is wanted or where just another Monitor Mode NIC is desired.

If using 2 NICs and Managed Mode you will need to leverage `--inj man` upon launch.

If using 2 NICs and Monitor mode simply assign with `-i` and `-m` accordingly.

If using `--tun` and Managed mode you do not need to invoke `--inj man` upon launch.

Open Wireless using 1 NIC
```
python3 ./airpwn-ng -i <Injecting NIC> -m <Monitoring NIC> --injection payloads/demo
```

Open Wireless using 2 NICs
```
python3 ./airpwn-ng -i <Injecting NIC> -m <Monitoring NIC> --inj man --injection payloads/demo
```

WEP using 1 NIC with airtun-ng
```
## Typical usage
airtun-ng -a <BSSID> -w <WEPKEY> <Monitoring NIC>
ifconfig at0 up
python3 ./airpwn-ng -i at0 -m at0 --tun --injection payloads/demo
```

WEP using 2 NICs with airtun-ng
```
## Niche usage
airtun-ng -a <BSSID> -w <WEPKEY> <Monitoring NIC>
ifconfig at0 up
python3 ./airpwn-ng -i <Injecting NIC> -m at0 --tun --injection payloads/demo
```

WPA using 1 NIC with airtun-ng
```
## Typical usage
airtun-ng -a <BSSID> -e <ESSID> -p <PSK> <Monitoring NIC>
ifconfig at0 up
python3 ./airpwn-ng -i at0 -m at0 --tun --injection payloads/demo
```

WPA using 2 NICs with airtun-ng
```
## Niche usage
airtun-ng -a <BSSID> -e <ESSID> -p <PSK> <Monitoring NIC>
ifconfig at0 up
python3 ./airpwn-ng -i <Injecting NIC> -m at0 --tun --injection payloads/demo
```

### Known issues
* [edgedressing](https://github.com/stryngs/edgedressing) will affect most modern Windows clients in a negative way.  In order to deal with how Windows figures out if it is online, the --trigger functionality should be utilized.  By default if --trigger is not called then 'GET /' becomes the string that airpwn-ng uses for understanding if an injection should occur or not.  This behavior is not ideal and may cause a Windows target to have connectivity issues if not adjusted for.

### Disclaimer
Illicit usage of this code has the potential to land the user in Legal and/or Civil jeopardy if used for malicious purposes or even unknowingly by perhaps using the wrong MAC filter as an example.  Ensure you know what the syntax you are running actually does.  airpwn-ng is a research tool aimed at demonstrating TCP injection.  The authors of airpwn-ng, airpwn and pretty much every other hacking tool out there take no, zip, zilch, zero and nada on the responsibility for what you the user does with it.
