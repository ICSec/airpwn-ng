from Queue import Queue, Empty
from pyDot11 import *
from scapy.layers.dot11 import Dot11, Dot11WEP
from scapy.layers.l2 import EAPOL
from scapy.sendrecv import sniff
from threading import Thread
import sys, time

class Sniffer(object):
    """This is the highest level object in the library.

    It uses an instance of Handler as the processing engine
    for packets received from scapy's sniff() function.
    """

    def __init__(self, packethandler, args, *positional_parameters, **keyword_parameters):
        if 'm' in keyword_parameters:
            self.m = keyword_parameters['m']
        else:
            self.m = None

        if self.m is None:
            print("[ERROR] No monitor interface selected")
            exit()

        self.packethandler = packethandler

        if args.wpa:
            self.shake = Handshake(args.wpa, args.essid, False)
            self.packethandler.injector.shake = self.shake

    def sniff(self, q):
        """Target function for Queue (multithreading)"""
        sniff(iface = self.m, prn = lambda x: q.put(x), lfilter = lambda x: x[Dot11].type == 2, store = 0)


    def handler(self, q, m, pkt, args):
        """This function exists solely to reduce lines of code"""

        ## WPA
        if args.wpa:
            eType = self.shake.encDict.get(self.tgtMAC)

            ### ccmp || tkip
            encKey = None
            if eType == 'ccmp':
                encKey = self.shake.tgtInfo.get(self.tgtMAC)[1]
            elif eType == 'tkip':
                encKey = self.shake.tgtInfo.get(self.tgtMAC)[0]

            ## Deal with pyDot11 bug
            if encKey is not None:

                ## Decrypt
                self.packethandler.injector.shake.origPkt, decodedPkt, self.packethandler.injector.shake.PN = wpaDecrypt(encKey, pkt, eType, False)

                ## Process
                self.packethandler.process(m, decodedPkt, args)

        ## WEP
        elif args.wep:

            ## Decrypt
            pkt, iVal = wepDecrypt(pkt, args.wep, False)

            ## Process
            self.packethandler.process(m, pkt, args)

        ## Open
        else:

            ## Process
            self.packethandler.process(m, pkt, args)
        q.task_done()


    def threaded_sniff(self, args):
        """This starts a Queue which receives packets and processes them.

        It uses the Handler.process function.
        Call this function to begin actual sniffing + injection.

        Useful reminder:
            to-DS is:    1L (open) / 65L (crypted)
            from-DS is:  2L (open) /66L (crypted)
        """
        q = Queue()
        sniffer = Thread(target = self.sniff, args = (q,))
        sniffer.daemon = True
        sniffer.start()

        ## Open
        if not args.wep and not args.wpa:
            while True:
                try:
                    pkt = q.get(timeout = 1)
                    if pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 1L:
                        self.handler(q, self.m, pkt, args)
                except Exception as E:
                    print(E)

        ## WEP
        elif args.wep:
            while True:
                try:
                    pkt = q.get(timeout = 1)
                    if pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65L:
                        self.handler(q, self.m, pkt, args)
                    else:
                        pass
                except Exception as E:
                    print(E)

        ## Sniffing in Monitor Mode for WPA
        elif args.wpa:
            while True:
                try:
                    pkt = q.get(timeout = 1)

                    if pkt.haslayer(EAPOL):
                        self.shake.eapolGrab(pkt)

                    elif pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65L:
                        self.tgtMAC = False

                        ## MAC verification
                        if pkt.addr1 in self.shake.availTgts:
                            self.tgtMAC = pkt.addr1
                        elif pkt.addr2 in self.shake.availTgts:
                            self.tgtMAC = pkt.addr2

                        ## Pass the packet
                        if self.tgtMAC:
                            self.handler(q, self.m, pkt, args)
                except Exception as E:
                    print(E)
