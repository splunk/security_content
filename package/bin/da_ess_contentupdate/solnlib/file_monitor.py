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
This module contains file monitoring class that can be used to check files
change periodically and call callback function to handle properly when
detecting files change.
'''

import time
import logging
import traceback
import threading
import os.path as op

__all__ = ['FileChangesChecker',
           'FileMonitor']


class FileChangesChecker(object):
    '''Files change checker.

    :param callback: Callback function for files change.
    :param files: Files to be monidtored with full path.
    :type files: ``list, tuple``
    '''

    def __init__(self, callback, files):
        self._callback = callback
        self._files = files

        self.file_mtimes = {file_name: None for file_name in self._files}
        for k in self.file_mtimes:
            try:
                self.file_mtimes[k] = op.getmtime(k)
            except OSError:
                logging.debug('Getmtime for %s, failed: %s', k,
                              traceback.format_exc())

    def check_changes(self):
        '''Check files change.

        If some files are changed and callback function is not None, call
        callback function to handle files change.

        :returns: True if files changed else False
        :rtype: ``bool``
        '''

        logging.debug('Checking files=%s', self._files)
        file_mtimes = self.file_mtimes
        changed_files = []
        for f, last_mtime in file_mtimes.iteritems():
            try:
                current_mtime = op.getmtime(f)
                if current_mtime != last_mtime:
                    file_mtimes[f] = current_mtime
                    changed_files.append(f)
                    logging.info('Detect %s has changed', f)
            except OSError:
                pass

        if changed_files:
            if self._callback:
                self._callback(changed_files)
            return True
        return False


class FileMonitor(object):
    '''Files change monitor.

    Monitor files change in a separated thread and call callback
    when there is files change.

    :param callback: Callback for handling files change.
    :param files: Files to monitor.
    :type files: ``list, tuple``
    :param interval: Interval to check files change.

    Usage::

      >>> import splunksolutionlib.file_monitor as fm
      >>> fm = fm.FileMonitor(fm_callback, files_list, 5)
      >>> fm.start()
    '''

    def __init__(self, callback, files, interval=1):
        self._checker = FileChangesChecker(callback, files)
        self._thr = threading.Thread(target=self._do_monitor)
        self._thr.daemon = True
        self._interval = interval
        self._started = False

    def start(self):
        '''Start file monitor.

        Start a background thread to monitor files change.
        '''

        if self._started:
            return
        self._started = True

        self._thr.start()

    def stop(self):
        '''Stop file monitor.

        Stop the background thread to monitor files change.
        '''

        self._started = False

    def _do_monitor(self):
        while self._started:
            self._checker.check_changes()

            for _ in xrange(self._interval):
                if not self._started:
                    break
                time.sleep(1)
