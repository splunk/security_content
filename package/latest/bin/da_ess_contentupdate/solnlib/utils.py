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
Common utilities.
'''

import datetime
import logging
import os
import signal
import time
import traceback
import urllib2
from functools import wraps

__all__ = ['handle_teardown_signals',
           'datetime_to_seconds',
           'is_true',
           'is_false',
           'escape_json_control_chars',
           'retry',
           'extract_http_scheme_host_port']


def handle_teardown_signals(callback):
    '''Register handler for SIGTERM/SIGINT/SIGBREAK signal.

    Catch SIGTERM/SIGINT/SIGBREAK signals, and invoke callback
    Note: this should be called in main thread since Python only catches
    signals in main thread.

    :param callback: Callback for tear down signals.
    :type callback: ``function``
    '''

    signal.signal(signal.SIGTERM, callback)
    signal.signal(signal.SIGINT, callback)

    if os.name == 'nt':
        signal.signal(signal.SIGBREAK, callback)


def datetime_to_seconds(dt):
    '''Convert UTC datatime to seconds since epoch.

    :param dt: Date time.
    :type dt: datetime.
    :returns: Seconds since epoch.
    :rtype: ``float``
    '''

    epoch_time = datetime.datetime.utcfromtimestamp(0)
    return (dt - epoch_time).total_seconds()


def is_true(val):
    '''Decide if `val` is true.

    :param val: Value to check.
    :type val: ``(integer, string)``
    :returns: True or False.
    :rtype: ``bool``
    '''

    value = str(val).strip().upper()
    if value in ('1', 'TRUE', 'T', 'Y', 'YES'):
        return True
    return False


def is_false(val):
    '''Decide if `val` is false.

    :param val: Value to check.
    :type val: ``(integer, string)``
    :returns: True or False.
    :rtype: ``bool``
    '''

    value = str(val).strip().upper()
    if value in ('0', 'FALSE', 'F', 'N', 'NO', 'NONE', ''):
        return True
    return False


def escape_json_control_chars(json_str):
    '''Escape json control chars in `json_str`.

    :param json_str: Json string to escape.
    :type json_str: ``string``
    :returns: Escaped string.
    :rtype: ``string``
    '''

    control_chars = ((r'\n', '\\\\n'),
                     (r'\r', '\\\\r'),
                     (r'\r\n', '\\\\r\\\\n'))
    for ch, replace in control_chars:
        json_str = json_str.replace(ch, replace)
    return json_str


def unescape_json_control_chars(json_str):
    '''Unescape json control chars in `json_str`.

    :param json_str: Json string to unescape.
    :type json_str: ``string``
    :returns: Unescaped string.
    :rtype: ``string``
    '''

    control_chars = (('\\\\n', r'\n'),
                     ('\\\\r', r'\r'),
                     ('\\\\r\\\\n', r'\r\n'))
    for ch, replace in control_chars:
        json_str = json_str.replace(ch, replace)
    return json_str


def retry(retries=3, reraise=True, default_return=None, exceptions=None):
    '''A decorator to run function with max `retries` times
    if there is exception.

    :param retries: (optional) Max retries times, default is 3.
    :type retries: ``integer``
    :param reraise: Whether exception should be reraised, default is True.
    :type reraise: ``bool``
    :param default_return: (optional) Default return value for function
        run after max retries and reraise is False.
    :param exceptions: (optional) List of exceptions that should retry.
    :type exceptions: ``list``
    '''

    max_tries = max(retries, 0) + 1

    def do_retry(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_ex = None
            for i in xrange(max_tries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    logging.warning('Run function: %s failed: %s.',
                                    func.__name__, traceback.format_exc(e))
                    if not exceptions or \
                            any(isinstance(e, exception) for exception in exceptions):
                        last_ex = e
                        if i < max_tries - 1:
                            time.sleep(2 ** i)
                    else:
                        raise

            if reraise:
                raise last_ex
            else:
                return default_return

        return wrapper

    return do_retry


def extract_http_scheme_host_port(http_url):
    '''Extract scheme, host and port from a HTTP URL.

    :param http_url: HTTP URL to extract.
    :type http_url: ``string``
    :returns: A tuple of scheme, host and port
    :rtype: ``tuple``

    :raises ValueError: If `http_url` is not in http(s)://hostname:port format.
    '''

    try:
        http_info = urllib2.urlparse.urlparse(http_url)
    except Exception:
        raise ValueError(
            str(http_url) + " is not in http(s)://hostname:port format")

    if not http_info.scheme or not http_info.hostname or not http_info.port:
        raise ValueError(
            http_url + " is not in http(s)://hostname:port format")

    return (http_info.scheme, http_info.hostname, http_info.port)
