class BadReportmodeVariable(Exception):
    def __init__(self, *args):
        if args:
            self.message = args[0]
        else:
            self.message = None

    def __str__(self):
        if self.message:
            return self.message
        else:
            return "Problem with 'reportmode' variable value."


class NotAPcap(Exception):
    def __str__(self):
        return "The provided file is not a valid pcap file."


class PythonTooOld(Exception):
    def __str__(self):
        return "Python version is too old. Must be run with at least Python 3.3"


class TsharkNotFound(Exception):
    def __str__(self):
        return "No Tshark instance found. Is it installed?"


class TsharkTooOld(Exception):
    def __str__(self):
        return "Tshark version is too old. At least Tshark 2.2.0 version required."
