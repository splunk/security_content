"""
A wrapper of multiprocessing.pool
"""

import multiprocessing
from ..common import log


class ProcessPool(object):
    """
    A simple wrapper of multiprocessing.pool
    """

    def __init__(self, size=0, maxtasksperchild=10000):
        if size <= 0:
            size = multiprocessing.cpu_count()
        self.size = size
        self._pool = multiprocessing.Pool(processes=size,
                                          maxtasksperchild=maxtasksperchild)
        self._stopped = False

    def tear_down(self):
        """
        Tear down the pool
        """

        if self._stopped:
            log.logger.info("ProcessPool has already stopped.")
            return
        self._stopped = True

        self._pool.close()
        self._pool.join()
        log.logger.info("ProcessPool stopped.")

    def apply(self, func, args=(), kwargs={}):
        """
        :param func: callable
        :param args: free params
        :param kwargs: named params
        :return whatever the func returns
        """

        if self._stopped:
            log.logger.info("ProcessPool has already stopped.")
            return None

        return self._pool.apply(func, args, kwargs)

    def apply_async(self, func, args=(), kwargs={}, callback=None):
        """
        :param func: callable
        :param args: free params
        :param kwargs: named params
        :callback: when func is done without exception, call this callack
        :return whatever the func returns
        """

        if self._stopped:
            log.logger.info("ProcessPool has already stopped.")
            return None

        return self._pool.apply_async(func, args, kwargs, callback)
