# Copyright 2016 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License'): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

'''
A simple thread safe timer queue implementation which has O(logn) time complexity.
'''

import Queue
import logging
import threading
import traceback
from time import time

from .packages import sortedcontainers as sc

__all__ = ['Timer',
           'TimerQueueStruct',
           'TimerQueue']


class Timer(object):
    '''Timer wraps the callback and timestamp related attributes.

    :param callback: Arbitrary callable object.
    :type callback: ``callable object``
    :param when: The first expiration time, seconds since epoch.
    :type when: ``integer``
    :param interval: Timer interval, if equals 0, one time timer, otherwise
        the timer will be periodically executed
    :type interval: ``integer``
    :param ident: (optional) Timer identity.
    :type ident:  ``integer``
    '''

    _ident = 0
    _lock = threading.Lock()

    def __init__(self, callback, when, interval, ident=None):
        self._callback = callback
        self.when = when
        self.interval = interval

        if ident is not None:
            self.ident = ident
        else:
            with Timer._lock:
                self.ident = Timer._ident + 1
                Timer._ident = Timer._ident + 1

    def update_expiration(self):
        self.when += self.interval

    def __cmp__(self, other):
        if other is None:
            return 1

        self_k = (self.when, self.ident)
        other_k = (other.when, other.ident)

        if self_k == other_k:
            return 0
        elif self_k < other_k:
            return -1
        else:
            return 1

    def __eq__(self, other):
        return isinstance(other, Timer) and (self.ident == other.ident)

    def __call__(self):
        self._callback()


TEARDOWN_SENTINEL = None


class TimerQueueStruct(object):
    '''
    The underlying data structure for TimerQueue
    '''

    def __init__(self):
        self._timers = sc.SortedSet()
        self._cancelling_timers = {}

    def add_timer(self, callback, when, interval, ident):
        ''' Add timer to the data structure.

        :param callback: Arbitrary callable object.
        :type callback: ``callable object``
        :param when: The first expiration time, seconds since epoch.
        :type when: ``integer``
        :param interval: Timer interval, if equals 0, one time timer, otherwise
            the timer will be periodically executed
        :type interval: ``integer``
        :param ident: (optional) Timer identity.
        :type ident:  ``integer``
        :returns: A timer object which should not be manipulated directly by
            clients. Used to delete/update the timer
        :rtype: ``solnlib.timer_queue.Timer``
        '''

        timer = Timer(callback, when, interval, ident)
        self._timers.add(timer)
        return timer

    def remove_timer(self, timer):
        ''' Remove timer from data structure.

        :param timer: Timer object which is returned by ``TimerQueueStruct.add_timer``.
        :type timer: ``Timer``
        '''

        try:
            self._timers.remove(timer)
        except ValueError:
            logging.info('Timer=%s is not in queue, move it to cancelling '
                         'list', timer.ident)
        else:
            self._cancelling_timers[timer.ident] = timer

    def get_expired_timers(self):
        ''' Get a list of expired timers.

        :returns: a list of ``Timer``, empty list if there is no expired
            timers.
        :rtype: ``list``
        '''

        next_expired_time = 0
        now = time()
        expired_timers = []
        for timer in self._timers:
            if timer.when <= now:
                expired_timers.append(timer)

        if expired_timers:
            del self._timers[:len(expired_timers)]

        if self._timers:
            next_expired_time = self._timers[0].when
        return (next_expired_time, expired_timers)

    def reset_timers(self, expired_timers):
        ''' Re-add the expired periodical timers to data structure for next
        round scheduling.

        :returns: True if there are timers added, False otherwise.
        :rtype: ``bool``
        '''

        has_new_timer = False
        cancelling_timers = self._cancelling_timers
        for timer in expired_timers:
            if timer.ident in cancelling_timers:
                logging.INFO('Timer=%s has been cancelled', timer.ident)
                continue
            elif timer.interval:
                # Repeated timer
                timer.update_expiration()
                self._timers.add(timer)
                has_new_timer = True
        cancelling_timers.clear()
        return has_new_timer

    def check_and_execute(self):
        ''' Get expired timers and execute callbacks for the timers.

        :returns: duration of next expired timer.
        :rtype: ``float``
        '''

        (next_expired_time, expired_timers) = self.get_expired_timers()
        for timer in expired_timers:
            try:
                timer()
            except Exception:
                logging.error(traceback.format_exc())

        self.reset_timers(expired_timers)
        return _calc_sleep_time(next_expired_time)


class TimerQueue(object):
    '''A simple timer queue implementation.

    It runs a separate thread to handle timers Note: to effectively use this
    timer queue, the timer callback should be short, otherwise it will cause
    other timers's delay execution. A typical use scenario in production is
    that the timers are just a simple functions which inject themselvies to
    a task queue and then they are picked up by a threading/process pool to
    execute, as shows below:
    Timers --enqueue---> TimerQueue --------expiration-----------
                                                                |
                                                                |
                                                               \|/
    Threading/Process Pool <---- TaskQueue <--enqueue-- Timers' callback (nonblocking)

    Usage::
           >>> from solnlib import time_queue
           >>> tq = time_queue.TimerQueue()
           >>> tq.start()
           >>> t = tq.add_timer(my_func, time.time(), 10)
           >>> # do other stuff
           >>> tq.stop()
    '''

    def __init__(self):
        self._timers = TimerQueueStruct()
        self._lock = threading.Lock()
        self._wakeup_queue = Queue.Queue()
        self._thr = threading.Thread(target=self._check_and_execute)
        self._thr.daemon = True
        self._started = False

    def start(self):
        '''Start the timer queue.
        '''

        if self._started:
            return
        self._started = True

        self._thr.start()
        logging.info('TimerQueue started.')

    def stop(self):
        '''Stop the timer queue.
        '''

        if not self._started:
            return
        self._started = True

        self._wakeup(TEARDOWN_SENTINEL)
        self._thr.join()

    def add_timer(self, callback, when, interval, ident=None):
        ''' Add timer to the queue.

        :param callback: Arbitrary callable object.
        :type callback: ``callable object``
        :param when: The first expiration time, seconds since epoch.
        :type when: ``integer``
        :param interval: Timer interval, if equals 0, one time timer, otherwise
            the timer will be periodically executed
        :type interval: ``integer``
        :param ident: (optional) Timer identity.
        :type ident:  ``integer``
        :returns: A timer object which should not be manipulated directly by
            clients. Used to delete/update the timer
        '''

        with self._lock:
            timer = self._timers.add_timer(callback, when, interval, ident)
        self._wakeup()
        return timer

    def remove_timer(self, timer):
        ''' Remove timer from the queue.

        :param timer: Timer object which is returned by ``TimerQueue.add_timer``.
        :type timer: ``Timer``
        '''

        with self._lock:
            self._timers.remove_timer(timer)

    def _check_and_execute(self):
        wakeup_queue = self._wakeup_queue
        while 1:
            (next_expired_time, expired_timers) = self._get_expired_timers()
            for timer in expired_timers:
                try:
                    # Note, please make timer callback effective/short
                    timer()
                except Exception:
                    logging.error(traceback.format_exc())

            self._reset_timers(expired_timers)

            sleep_time = _calc_sleep_time(next_expired_time)
            try:
                wakeup = wakeup_queue.get(timeout=sleep_time)
                if wakeup is TEARDOWN_SENTINEL:
                    break
            except Queue.Empty:
                pass
        logging.info('TimerQueue stopped.')

    def _get_expired_timers(self):
        with self._lock:
            return self._timers.get_expired_timers()

    def _reset_timers(self, expired_timers):
        with self._lock:
            has_new_timer = self._timers.reset_timers(expired_timers)

        if has_new_timer:
            self._wakeup()

    def _wakeup(self, something='not_None'):
        self._wakeup_queue.put(something)


def _calc_sleep_time(next_expired_time):
    if next_expired_time:
        now = time()
        if now < next_expired_time:
            sleep_time = next_expired_time - now
        else:
            sleep_time = 0.1
    else:
        sleep_time = 1
    return sleep_time
