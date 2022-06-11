import argparse
import os
import signal
import subprocess
import sys
from airpwn_ng.lib.styles import File
from airpwn_ng.lib.visuals import Bcolors

class Core(object):

    def __init__(self, args):
        self.args = args


    def crtlC(self, args):
        """Handle CTRL+C."""
        def tmp(signal, frame):
            print (Bcolors.FAIL + '\n[!] Stopping injection and exiting airpwn-ng ...' + Bcolors.ENDC)
            sys.exit(0)
        return tmp


    def channelSet(self, nic, chan):
        """Set the channel for a given NIC"""
        subprocess.call('iwconfig {0} channel {1}'.format(nic, chan), shell = True)


    def injection_check(self, args):
        """Injection file check"""
        try:
            f = open(self.args.injection, 'r')
            f.close()
        except:
            print (Bcolors.FAIL + '[!] Selected injection file', self.args.injection, 'does not exist.' + Bcolors.ENDC)
            exit(1)
        print (Bcolors.OKGREEN + '\n[+] Loaded injection file {0}'.format(str(self.args.injection)) + Bcolors.ENDC)
        injection = 1
        return injection


    def main(self):
        """Launching logic"""

        ## Backpressure defaults
        if self.args.w is not None:
            self.args.bWarn = int(self.args.w)
        else:
            self.args.bWarn = 40

        ## NIC types
        if self.args.inj is None:
            self.args.inj = 'mon'

        ## Set channel if so desired
        if self.args.channel is not None:
            if self.args.tun is False:
                print (Bcolors.OKGREEN + '[+] Setting NIC Channel(s) to %s' % self.args.channel + Bcolors.ENDC)

                ## Set monitor nic
                self.channelSet(self.args.m, self.args.channel)

                ## Set injector nic
                if self.args.inj == 'mon':
                    self.channelSet(self.args.i, self.args.channel)

        ## Injection Logic
        injection = self.injection_check(self.args)

        ## BSSID announce
        if self.args.bssid is not None:
            print (Bcolors.OKGREEN + '[+] Adding BSSID  ' + Bcolors.OKBLUE + self.args.bssid + Bcolors.ENDC)

        ## Broadcast mode
        if self.args.t is None:
            print (Bcolors.WARNING + '[!] You are in broadcast mode.')
            print ('[!] This means you will inject packets into all targetss you are able to detect.')
            print ('[!] Use with caution.' + Bcolors.ENDC)

        ## Targeted mode
        else:
            if len(self.args.t) == 0:
                print (Bcolors.WARNING + '[!] You must specify at least one target MAC address with -t for targeted mode')
                exit(1)
            else:
                for target in self.args.t:
                    print (Bcolors.OKGREEN + '[+] Adding target ' + Bcolors.OKBLUE + target + Bcolors.ENDC)

        ## Launch the handler
        style = File()
        style.handler(self.args)
