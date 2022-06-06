class Tracker(object):
    """The Tracker class is a found target.  It is defined via the ip and mac.

    Instantiates for each target for when sniffing
    """

    def __init__(self, *positional_parameters, **keyword_parameters):
        self.ip = keyword_parameters.get('ip')
        self.mac = keyword_parameters.get('mac')
        self.tParams = keyword_parameters['tParams']


    def get_injection(self):
        """Opportunistic target injections"""
        if self.tParams.in_request is None:
            if self.tParams.file_injected == 0:
                return self.tParams.file_inject
