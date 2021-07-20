from lib.packet_handler import PacketHandler
from lib.parameters import VictimParameters
from lib.sniffer import Sniffer
from lib.victim import Victim

class File(object):
    """Inject based upon a single file"""

    def handler(self, args):
        """Handle injection using the contents of a given file"""

        ## Victim parameters
        if args.covert:
            vp = VictimParameters(inject_file = args.injection, covert = args.covert)
        else:
            vp = VictimParameters(inject_file = args.injection)

        ## Broadcast mode
        if not args.t:
            ph = PacketHandler(Args = args, i = args.i, victim_parameters = vp)

        ## Targeted mode
        else:
            victims = []
            for victim in args.t:
                v1 = Victim(mac = victim, victim_parameters = vp)
                victims.append(v1)

            ph = PacketHandler(Args = args, i = args.i, victims = victims)

        ## Begin sniffing
        snif = Sniffer(ph, args, m = args.m)
        snif.threaded_sniff(args) ## Here
