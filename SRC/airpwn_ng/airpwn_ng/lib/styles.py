from .packet_handler import PacketHandler
from .parameters import TargetParameters
from .sniffer import Sniffer
from .target import Target

class File(object):
    """Inject based upon a single file"""

    def handler(self, args):
        """Handle injection using the contents of a given file"""

        ## Target parameters
        tp = TargetParameters(inject_file = args.injection)

        ## Packet handling
        ph = PacketHandler(Args = args, i = args.i, target_parameters = tp)

        ## Begin sniffing
        snif = Sniffer(ph, args, m = args.m)
        snif.threaded_sniff(args)
