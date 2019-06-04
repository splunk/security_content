"""
A simple thread pool implementation
"""

import threading
import Queue
import multiprocessing
import traceback
import exceptions
from time import time

from ..common import log


class ThreadPool(object):
    """
    A simple thread pool implementation
    """

    _high_watermark = 0.2
    _resize_window = 10

    def __init__(self, min_size=1, max_size=128,
                 task_queue_size=1024, daemon=True):
        assert task_queue_size

        if not min_size or min_size <= 0:
            min_size = multiprocessing.cpu_count()

        if not max_size or max_size <= 0:
            max_size = multiprocessing.cpu_count() * 8

        self._min_size = min_size
        self._max_size = max_size
        self._daemon = daemon

        self._work_queue = Queue.Queue(task_queue_size)
        self._thrs = []
        for _ in range(min_size):
            thr = threading.Thread(target=self._run)
            self._thrs.append(thr)
        self._admin_queue = Queue.Queue()
        self._admin_thr = threading.Thread(target=self._do_admin)
        self._last_resize_time = time()
        self._last_size = min_size
        self._lock = threading.Lock()
        self._occupied_threads = 0
        self._count_lock = threading.Lock()
        self._started = False

    def start(self):
        """
        Start threads in the pool
        """

        with self._lock:
            if self._started:
                return
            self._started = True

            for thr in self._thrs:
                thr.daemon = self._daemon
                thr.start()

            self._admin_thr.start()
        log.logger.info("ThreadPool started.")

    def tear_down(self):
        """
        Tear down thread pool
        """

        with self._lock:
            if not self._started:
                return
            self._started = False

            for thr in self._thrs:
                self._work_queue.put(None, block=True)

            self._admin_queue.put(None)

            if not self._daemon:
                log.logger.info("Wait for threads to stop.")
                for thr in self._thrs:
                    thr.join()
            self._admin_thr.join()

        log.logger.info("ThreadPool stopped.")

    def enqueue_funcs(self, funcs, block=True):
        """
        run jobs in a fire and forget way, no result will be handled
        over to clients
        :param funcs: tuple/list-like or generator like object, func shall be
                      callable
        """

        if not self._started:
            log.logger.info("ThreadPool has already stopped.")
            return

        for func in funcs:
            self._work_queue.put(func, block)

    def apply_async(self, func, args=(), kwargs=None, callback=None):
        """
        :param func: callable
        :param args: free params
        :param kwargs: named params
        :callback: when func is done and without exception, call the callback
        :return AsyncResult, clients can poll or wait the result through it
        """

        if not self._started:
            log.logger.info("ThreadPool has already stopped.")
            return None

        res = AsyncResult(func, args, kwargs, callback)
        self._work_queue.put(res)
        return res

    def apply(self, func, args=(), kwargs=None):
        """
        :param func: callable
        :param args: free params
        :param kwargs: named params
        :return whatever the func returns
        """

        if not self._started:
            log.logger.info("ThreadPool has already stopped.")
            return None

        res = self.apply_async(func, args, kwargs)
        return res.get()

    def size(self):
        return self._last_size

    def resize(self, new_size):
        """
        Resize the pool size, spawn or destroy threads if necessary
        """

        if new_size <= 0:
            return

        if self._lock.locked() or not self._started:
            log.logger.info("Try to resize thread pool during the tear "
                            "down process, do nothing")
            return

        with self._lock:
            self._remove_exited_threads_with_lock()
            size = self._last_size
            self._last_size = new_size
            if new_size > size:
                for _ in xrange(new_size - size):
                    thr = threading.Thread(target=self._run)
                    thr.daemon = self._daemon
                    thr.start()
                    self._thrs.append(thr)
            elif new_size < size:
                for _ in xrange(size - new_size):
                    self._work_queue.put(None)
        log.logger.info("Finished ThreadPool resizing. New size=%d", new_size)

    def _remove_exited_threads_with_lock(self):
        """
        Join the exited threads last time when resize was called
        """

        joined_thrs = set()
        for thr in self._thrs:
            if not thr.is_alive():
                try:
                    if not thr.daemon:
                        thr.join(timeout=0.5)
                    joined_thrs.add(thr.ident)
                except RuntimeError:
                    pass

        if joined_thrs:
            live_thrs = []
            for thr in self._thrs:
                if thr.ident not in joined_thrs:
                    live_thrs.append(thr)
            self._thrs = live_thrs

    def _do_resize_according_to_loads(self):
        if (self._last_resize_time and
                time() - self._last_resize_time < self._resize_window):
            return

        thr_size = self._last_size
        free_thrs = thr_size - self._occupied_threads
        work_size = self._work_queue.qsize()

        log.logger.debug("current_thr_size=%s, free_thrs=%s, work_size=%s",
                        thr_size, free_thrs, work_size)
        if work_size and work_size > free_thrs:
            if thr_size < self._max_size:
                thr_size = min(thr_size * 2, self._max_size)
                self.resize(thr_size)
        elif free_thrs > 0:
            free = free_thrs * 1.0
            if free / thr_size >= self._high_watermark and free_thrs >= 2:
                # 20 % thrs are idle, tear down half of the idle ones
                thr_size = thr_size - free_thrs / 2
                if thr_size > self._min_size:
                    self.resize(thr_size)
        self._last_resize_time = time()

    def _do_admin(self):
        admin_q = self._admin_queue
        resize_win = self._resize_window
        while 1:
            try:
                wakup = admin_q.get(timeout=resize_win + 1)
            except Queue.Empty:
                self._do_resize_according_to_loads()
                continue

            if wakup is None:
                break
            else:
                self._do_resize_according_to_loads()
        log.logger.info("ThreadPool admin thread=%s stopped.",
                        threading.current_thread().getName())

    def _run(self):
        """
        Threads callback func, run forever to handle jobs from the job queue
        """

        work_queue = self._work_queue
        count_lock = self._count_lock
        while 1:
            log.logger.debug("Going to get job")
            func = work_queue.get()
            if func is None:
                break

            if not self._started:
                break

            log.logger.debug("Going to exec job")
            with count_lock:
                self._occupied_threads += 1

            try:
                func()
            except Exception:
                log.logger.error(traceback.format_exc())

            with count_lock:
                self._occupied_threads -= 1

            log.logger.debug("Done with exec job")
            log.logger.info("Thread work_queue_size=%d", work_queue.qsize())

        log.logger.debug("Worker thread %s stopped.",
                         threading.current_thread().getName())


class AsyncResult(object):

    def __init__(self, func, args, kwargs, callback):
        self._func = func
        self._args = args
        self._kwargs = kwargs
        self._callback = callback
        self._q = Queue.Queue()

    def __call__(self):
        try:
            if self._args and self._kwargs:
                res = self._func(*self._args, **self._kwargs)
            elif self._args:
                res = self._func(*self._args)
            elif self._kwargs:
                res = self._func(**self._kwargs)
            else:
                res = self._func()
        except Exception as e:
            self._q.put(e)
            return
        else:
            self._q.put(res)

        if self._callback is not None:
            self._callback()

    def get(self, timeout=None):
        """
        Return the result when it arrives. If timeout is not None and the
        result does not arrive within timeout seconds then
        multiprocessing.TimeoutError is raised. If the remote call raised an
        exception then that exception will be reraised by get().
        """

        try:
            res = self._q.get(timeout=timeout)
        except Queue.Empty:
            raise multiprocessing.TimeoutError("Timed out")

        if isinstance(res, Exception):
            raise res
        return res

    def wait(self, timeout=None):
        """
        Wait until the result is available or until timeout seconds pass.
        """

        try:
            res = self._q.get(timeout=timeout)
        except Queue.Empty:
            pass
        else:
            self._q.put(res)

    def ready(self):
        """
        Return whether the call has completed.
        """

        return len(self._q)

    def successful(self):
        """
        Return whether the call completed without raising an exception.
        Will raise AssertionError if the result is not ready.
        """

        if not self.ready():
            raise exceptions.AssertionError("Function is not ready")
        res = self._q.get()
        self._q.put(res)

        if isinstance(res, Exception):
            return False
        return True
