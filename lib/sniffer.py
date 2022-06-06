import sys
import time
from lib.visuals import Bcolors
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

    def __init__(self, packethandler, args, *positional_parameters, **keyword_parameters):
        self.m = keyword_parameters.get('m')

        ## Create the handler
        self.packethandler = packethandler

        ## Backpressure warnings
        self.bp = args.bWarn


    def sniff(self, q):
        """Target function for Queue (multithreading)"""
        sniff(iface = self.m, prn = lambda x: q.put(x), store = 0)


    def threaded_sniff(self, args):
        """This starts a Queue which receives packets and processes them.

        It uses the PacketHandler.process function.
        Call this function to begin actual sniffing + injection.

        Useful reminder:
            to-DS is:    1 (open) / 65 (crypted)
            from-DS is:  2 (open) / 66 (crypted)

        Need to look into sending other than 1/65 or 2/66
        Probably get more success...

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
                if args.tun is False:

                    ## Process and finish out the task
                    if pkt[Dot11].FCfield == 1:
                        self.packethandler.process(self.m, pkt, args)
                        q.task_done()

                ## Process and finish out the task
                else:
                    self.packethandler.process(self.m, pkt, args)
                    q.task_done()
            except Empty:
                pass
