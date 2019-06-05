import threading


class Timer(object):
    """
    Timer wraps the callback and timestamp related stuff
    """

    _ident = 0
    _lock = threading.Lock()

    def __init__(self, callback, when, interval, ident=None):
        self._callback = callback
        self._when = when
        self._interval = interval

        if ident is not None:
            self._id = ident
        else:
            with Timer._lock:
                self._id = Timer._ident + 1
                Timer._ident = Timer._ident + 1

    def get_interval(self):
        return self._interval

    def set_interval(self, interval):
        self._interval = interval

    def get_expiration(self):
        return self._when

    def set_initial_due_time(self, when):
        self._when = when

    def update_expiration(self):
        self._when += self._interval

    def __cmp__(self, other):
        if other is None:
            return 1

        self_k = (self.get_expiration(), self.ident())
        other_k = (other.get_expiration(), other.ident())

        if self_k == other_k:
            return 0
        elif self_k < other_k:
            return -1
        else:
            return 1

    def __eq__(self, other):
        return isinstance(other, Timer) and (self.ident() == other.ident())

    def __call__(self):
        self._callback()

    def ident(self):
        return self._id
