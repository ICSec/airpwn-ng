class TargetParams(object):
    """Parameters for each targeted Instantiation of Tracker()"""

    def __init__(self, *positional_parameters, **keyword_parameters):
        self.inject_file = keyword_parameters['inject_file']
        self.in_request = None
        self.in_request_handler = None
        self.file_inject = self.load_injection(self.inject_file)
        self.file_injected = 0


    def load_injection(self, injectionfile):
        """Loads an injection from file if --injection is set."""
        f = open(injectionfile, 'r')
        try:
            data = f.read()
        finally:
            f.close()
        return data
