import argparse

class Menu(object):

    def __init__(self):
        self.parser = argparse.ArgumentParser(description = 'airpwn-ng - the new and improved 802.11 packet injector')
        self.parser.add_argument('-i',
                            help = 'Your injection interface',
                            metavar = '<interface>')
        self.parser.add_argument('-m',
                            help = 'Your monitor interface',
                            metavar = '<interface>')
        self.parser.add_argument('-t',
                            help = 'Target MAC addresses',
                            metavar = '<MAC address>',
                            nargs = '*')
        self.parser.add_argument('-w',
                            help = 'Backpressure warning value',
                            metavar = 'Backpressure warning value')
        self.parser.add_argument('--bssid',
                            help = 'Filter for a given BSSID',
                            metavar = 'Filter for a given BSSID')
        self.parser.add_argument('--channel',
                            help = 'Set the channel for the NICs',
                            metavar = '<channel>')
        self.parser.add_argument('--inj',
                            choices = ['mon', 'man'],
                            help = 'Injector NIC type - mon or man',
                            metavar = '<inj NIC type>')
        self.parser.add_argument('--injection',
                            metavar = '<filename>',
                            help = 'File with your injection code',
                            required = True)
        self.parser.add_argument('--trigger',
                            metavar = '<trigger>',
                            help = 'Trigger string for injection')
        self.parser.add_argument('--tun',
                            action = 'store_true',
                            help = 'airtun-ng integration')
