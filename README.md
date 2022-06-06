
# Concept
airpwn-ng is a framework for 802.11 (wireless) packet injection.  airpwn-ng listens to incoming wireless packets, and if the data matches a specified trigger, custom content is injected. From the perspective of the wireless client, airpwn-ng is the server.

airpwn-ng is based on the concepts laid out in [Airpwn](http://airpwn.sourceforge.net/Airpwn.html).

## How does this work?
* http://airpwn.sourceforge.net/Documentation.html
* https://github.com/ICSec/dc25

## Requirements
* https://www.aircrack-ng.org/install.html
* ```python3 -m pip install RESOURCEs/*.tar.gz```

## Example usage
Open Wireless using 1 NIC
```
python3 ./airpwn-ng -i <Injecting NIC> -m <Monitoring NIC> --injection payloads/demo
```

Open Wireless using 2 NICs
```
## Assumes the NIC designated for injection is in a managed state
python3 ./airpwn-ng -i <Injecting NIC> -m <Monitoring NIC> --injection payloads/demo --inj man
```

WEP using 1 NIC with airtun-ng
```
## Typical usage
airtun-ng -a <BSSID> -w <WEPKEY> <Monitoring NIC>
python3 ./airpwn-ng -i at0 -m at0 --injection payloads/demo --tun
```

WEP using 2 NICs with airtun-ng
```
## Niche usage
airtun-ng -a <BSSID> -w <WEPKEY> <Monitoring NIC>
python3 ./airpwn-ng -i <Injecting NIC> -m at0 --injection payloads/demo --inj man --tun
```

WPA using 1 NIC with airtun-ng
```
## Typical usage
airtun-ng -a <BSSID> -e <ESSID> -p <PSK> <Monitoring NIC>
python3 ./airpwn-ng -i at0 -m at0 --tun --injection payloads/demo
```

WPA using 2 NICs with airtun-ng
```
## Niche usage
airtun-ng -a <BSSID> -e <ESSID> -p <PSK> <Monitoring NIC>
python3 ./airpwn-ng -i <Injecting NIC> -m at0 --tun --injection payloads/demo --inj man
```

### Known issues
* [edgedressing](https://github.com/stryngs/edgedressing) will affect most modern Windows clients in a negative way.  In order to deal with how Windows figures out if it is online, the --trigger functionality should be utilized.  By default if --trigger is not called then 'GET /' becomes the string that airpwn-ng uses for understanding if an injection should occur or not.  This behavior is not ideal and may cause a Windows target to have connectivity issues if not adjusted for.
* BSSID and MAC Targeting needs further testing for bugs.
* Removal of older options is currently underway, anything marked deprecated will eventually be removed.

### Disclaimer
Illicit usage of this code has the potential to land the user in Legal and/or Civil jeopardy if used for malicious purposes or even unknowingly by perhaps using the wrong MAC filter as an example.  Ensure you know what the syntax you are running actually does.  Even better, have a glance at the source code to make sure for yourself.  Better than that, help us write a wiki on how this whole thing is put together for the betterment of society.  airpwn-ng is a tool meant for legal and ethical purposes.  The authors of airpwn-ng, airpwn and pretty much every other hacking tool out there take no, zip, zilch, zero and nada on the responsibility for what you the user does with it.

[![Join the chat at https://gitter.im/ICSec/airpwn-ng](https://badges.gitter.im/ICSec/airpwn-ng.svg)](https://gitter.im/ICSec/airpwn-ng?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
