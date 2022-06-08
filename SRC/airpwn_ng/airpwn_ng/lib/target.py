from .visuals import Bcolors

class Target(object):
    """A leftover class from the original airpwn-ng implementation.

    This class is slowly being phased out.
    """

    def __init__(self, *positional_parameters, **keyword_parameters):
        self.mac = keyword_parameters.get('mac')
        self.target_parameters = keyword_parameters.get('target_parameters')

        if self.ip is None and self.mac is None:
            print ('[ERROR] Target: No IP or Mac, or in_request selected')
            exit(1)

        if self.target_parameters is None:
            print ('[ERROR] Please create TargetParameters for this Target')
            exit(1)
