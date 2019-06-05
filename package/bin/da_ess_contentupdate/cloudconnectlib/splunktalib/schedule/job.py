import threading
import time


class Job(object):
    """
    Timer wraps the callback and timestamp related stuff
    """

    _ident = 0
    _lock = threading.Lock()

    def __init__(self, func, job_props, interval, when=None, job_id=None):
        """
        @job_props: dict like object
        @func: execution function
        @interval: execution interval
        @when: seconds from epoch
        @job_id: a unique id for the job
        """

        self._props = job_props
        self._func = func
        if when is None:
            self._when = time.time()
        else:
            self._when = when
        self._interval = interval

        if job_id is not None:
            self._id = job_id
        else:
            with Job._lock:
                self._id = Job._ident + 1
                Job._ident = Job._ident + 1
        self._stopped = False

    def ident(self):
        return self._id

    def get_interval(self):
        return self._interval

    def set_interval(self, interval):
        self._interval = interval

    def get_expiration(self):
        return self._when

    def set_initial_due_time(self, when):
        if self._when is None:
            self._when = when

    def update_expiration(self):
        self._when += self._interval

    def get(self, key, default):
        return self._props.get(key, default)

    def get_props(self):
        return self._props

    def set_props(self, props):
        self._props = props

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
        return isinstance(other, Job) and (self.ident() == other.ident())

    def __call__(self):
        self._func(self)

    def stop(self):
        self._stopped = True

    def stopped(self):
        return self._stopped
