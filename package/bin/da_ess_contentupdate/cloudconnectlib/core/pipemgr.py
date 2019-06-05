from solnlib.pattern import Singleton


class PipeManager(object):
    __metaclass__ = Singleton

    def __init__(self, event_writer=None):
        self._event_writer = event_writer

    def write_events(self, events):
        if not self._event_writer:
            print events
            return True
        return self._event_writer.write_events(events)
