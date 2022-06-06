from lib.visuals import Bcolors

class Victim(object):
    """Victim class is your target, define it by setting ip or mac address.

    It needs an instance of VictimParameters, where you set what you want to inject per victim.
    This allows for different attacks per target.
    This class is used by PacketHandler class.
    """

    def __init__(self, *positional_parameters, **keyword_parameters):
        self.cookies = []
        self.ip = keyword_parameters.get('ip')
        self.mac = keyword_parameters.get('mac')
        self.victim_parameters = keyword_parameters.get('victim_parameters')

        if self.ip is None and self.mac is None:
            print ('[ERROR] Victim: No IP or Mac, or in_request selected')
            exit(1)

        if self.victim_parameters is None:
            print ('[ERROR] Please create VictimParameters for this Victim')
            exit(1)


    def get_injection(self):
        '''Returns injection for victim
        
        gutting for speed -- soon to remove'''
        return self.victim_parameters.file_inject

