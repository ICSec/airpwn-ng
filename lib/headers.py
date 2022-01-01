import time

class Headers(object):
    """ Headers class

        This class is where the user can add new headers.
        This class might become file based, but for now, module.
    """

    def default(self, injection):
        """ Create the HTML headers """
        return '\r\n'.join(['HTTP/1.1 200 OK',
                            'Date: {}'.format(time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())),
                            'Server: Apache',
                            'Content-Length: {}'.format(len(injection)),
                            'Connection: close',
                            'Content-Type: text/html\r\n\r\n'])
