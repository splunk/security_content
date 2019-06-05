"""
A timer queue implementation
"""

import threading
import Queue
from time import time
import traceback

from .timer import Timer
from .common import log


class TimerQueue(object):
    """
    A timer queue implementation, runs a separate thread to handle timers
    """

    import sortedcontainers as sc

    def __init__(self):
        self._timers = TimerQueue.sc.SortedSet()
        self._cancelling_timers = {}
        self._lock = threading.Lock()
        self._wakeup_queue = Queue.Queue()
        self._thr = threading.Thread(target=self._check_and_execute)
        self._started = False

    def start(self):
        """
        Start the timer queue to make it start function
        """

        if self._started:
            return
        self._started = True

        self._thr.start()
        log.logger.info("TimerQueue started.")

    def tear_down(self):
        if not self._started:
            return
        self._started = True
        self._wakeup(None)
        self._thr.join()

    def add_timer(self, callback, when, interval):
        """
        Add timer to the queue
        """

        timer = Timer(callback, when, interval)
        with self._lock:
            self._timers.add(timer)
        self._wakeup()
        return timer

    def remove_timer(self, timer):
        """
        Remove timer from the queue.
        """

        with self._lock:
            try:
                self._timers.remove(timer)
            except ValueError:
                log.logger.info("Timer=%s is not in queue, move it to cancelling "
                                "list", timer.ident())
            else:
                self._cancelling_timers[timer.ident()] = timer

    def _check_and_execute(self):
        wakeup_queue = self._wakeup_queue
        while 1:
            (next_expired_time, expired_timers) = self._get_expired_timers()
            for timer in expired_timers:
                try:
                    timer()
                except Exception:
                    log.logger.error(traceback.format_exc())

            self._reset_timers(expired_timers)

            # Calc sleep time
            if next_expired_time:
                now = time()
                if now < next_expired_time:
                    sleep_time = next_expired_time - now
                else:
                    sleep_time = 0.1
            else:
                sleep_time = 1

            try:
                wakeup = wakeup_queue.get(timeout=sleep_time)
                if wakeup is None:
                    break
            except Queue.Empty:
                pass
        log.logger.info("TimerQueue stopped.")

    def _get_expired_timers(self):
        next_expired_time = 0
        now = time()
        expired_timers = []
        with self._lock:
            for timer in self._timers:
                if timer.get_expiration() <= now:
                    expired_timers.append(timer)

            if expired_timers:
                del self._timers[:len(expired_timers)]

            if self._timers:
                next_expired_time = self._timers[0].get_expiration()
        return (next_expired_time, expired_timers)

    def _reset_timers(self, expired_timers):
        has_new_timer = False
        with self._lock:
            cancelling_timers = self._cancelling_timers
            for timer in expired_timers:
                if timer.ident() in cancelling_timers:
                    log.logger.INFO("Timer=%s has been cancelled", timer.ident())
                    continue
                elif timer.get_interval():
                    # Repeated timer
                    timer.update_expiration()
                    self._timers.add(timer)
                    has_new_timer = True
            cancelling_timers.clear()

        if has_new_timer:
            self._wakeup()

    def _wakeup(self, something="not_None"):
        self._wakeup_queue.put(something)
