import time
from .visuals import Bcolors
from queue import Queue, Empty
from scapy.layers.dot11 import Dot11, Dot11FCS, Dot11WEP
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sniff
from threading import Thread

class Sniffer(object):
    """This is the highest level object in the library.

    It uses an instance of PacketHandler as the processing engine
    for packets received from scapy's sniff() function.
    """
    __slots__ = ('bp',
                 'bssid',
                 'm',
                 'packethandler',
                 'tgtList',
                 'tun')

    def __init__(self, packethandler, args):
        self.m = args.m
        self.tun = args.tun

        ## Create the handler
        self.packethandler = packethandler

        ## Backpressure warnings
        self.bp = args.bWarn
        self.bssid = args.bssid
        self.tgtList = args.t


    def sniff(self, q):
        """Handles the logic for sniffing setup.
        
        Ignores frames with the FromDS bit set in Open for speed.
        Encrypted expects airtun-ng or a retooling/implementation of pyDot11.
        """

        ## Open
        if not self.tun:

            ## Sniff all clients
            if self.tgtList is None:

                ## Sniff all BSSIDs
                if self.bssid is None:
                    sniff(iface = self.m, prn = lambda x: q.put(x), store = 0, filter = 'wlan[1] & 0x01 != 0 and wlan[1] & 0x02 == 0')

                ## Sniff one BSSID
                else:
                    sniff(iface = self.m, prn = lambda x: q.put(x), store = 0, filter = f'wlan addr1 {self.bssid} and wlan[1] & 0x01 != 0 and wlan[1] & 0x02 == 0')

            ## Sniff one client
            else:

                ## Sniff all BSSIDs
                if self.bssid is None:
                    sniff(iface = self.m, prn = lambda x: q.put(x), store = 0, filter = f'wlan addr2 {self.tgtList[0]} and wlan[1] & 0x01 != 0 and wlan[1] & 0x02 == 0')

                ## Sniff one BSSID
                else:
                    sniff(iface = self.m, prn = lambda x: q.put(x), store = 0, filter = f'wlan addr1 {self.bssid} and wlan addr2 {self.tgtList[0]} and wlan[1] & 0x01 != 0 and wlan[1] & 0x02 == 0')
       
        ## Encrypted
        else:

            ## Sniff everything
            if self.tgtList is None:
                sniff(iface = self.m, prn = lambda x: q.put(x), store = 0)

            ## Sniff targeted
            else:
                sniff(iface = self.m, prn = lambda x: q.put(x), store = 0, filter = f'ether host {self.tgtList[0]}')


    def threaded_sniff(self, args):
        """This starts a Queue which receives packets and processes them.

        It uses the PacketHandler.process function.
        Call this function to begin actual sniffing + injection.
        """
        q = Queue()
        sniffer = Thread(target = self.sniff, args = (q,))
        sniffer.daemon = True
        sniffer.start()
        warningTimer = 0

        while True:
            try:
                x = q.qsize()
                if x > self.bp:
                    if time.time() - warningTimer > 5:
                        print('                                                                               {0} backpressure warning'.format(q.qsize()))
                        warningTimer = time.time()
                pkt = q.get(timeout = 1)
                try:
                    if args.tun is False:
                        # Driver? workaround from foxHunter.py ln# 7 (https://github.com/stryngs/foxHunter/commit/2b5d99562688911937ebc3ddd319ced122488f56)
                        if not hasattr(pkt, 'FCfield'):
                            continue

                        if pkt[Dot11].FCfield.to_DS:
                            self.packethandler.process(self.m, pkt, args)
                    else:
                        self.packethandler.process(self.m, pkt, args)
                finally:
                    q.task_done()
            except Empty:
                pass
