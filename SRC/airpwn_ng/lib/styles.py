from .packet_handler import PacketHandler
from .parameters import TargetParameters
from .sniffer import Sniffer
from .target import Target

"""
This module allows for multiple vectors in reference to injection.

The default model is to inject based off of a templated file.
"""

class File(object):
    """Inject based upon a single file"""

    def handler(self, args):
        """Handle injection using the contents of a given file"""

        ## Target parameters
        tp = TargetParameters(inject_file = args.injection)

        ## Packet handling
        # ph = PacketHandler(Args = args, i = args.i, target_parameters = tp)
        ph = PacketHandler(args, tp)

        ## Begin sniffing
        snif = Sniffer(ph, args)
        snif.threaded_sniff(args)
