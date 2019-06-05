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
Net utilities.
'''
import inspect
import itertools
import re
import socket
from functools import wraps

from . import ip_math

__all__ = ['resolve_hostname']


def resolve_hostname(addr):
    '''Try to resolve an IP to a host name and returns None
    on common failures.

    :param addr: IP address to resolve.
    :type addr: ``string``
    :returns: Host name if success else None.
    :rtype: ``string``

    :raises ValueError: If `addr` is not a valid address
    '''

    if ip_math.is_valid_ip(addr):
        try:
            name, _, _ = socket.gethostbyaddr(addr)
            return name
        except socket.gaierror:
            # [Errno 8] nodename nor servname provided, or not known
            pass
        except socket.herror:
            # [Errno 1] Unknown host
            pass
        except socket.timeout:
            # Timeout.
            pass

        return None
    else:
        raise ValueError('Invalid ip address.')


def is_valid_hostname(hostname):
    '''Validate a host name.

    :param hostname: host name to validate.
    :type hostname: ``string``
    :returns: True if is valid else False
    :rtype: ``bool``
    '''

    if len(hostname) > 255:
        return False
    if hostname[-1:] == '.':
        hostname = hostname[:-1]
    allowed = re.compile('(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split('.'))


def is_valid_port(port):
    '''Validate a port.

    :param port: port to validate.
    :type port: ``(string, int)``
    :returns: True if is valid else False
    :rtype: ``bool``
    '''

    try:
        return 0 < int(port) <= 65535
    except ValueError:
        return False


def is_valid_scheme(scheme):
    '''Validate a scheme.

    :param scheme: scheme to validate.
    :type scheme: ``string``
    :returns: True if is valid else False
    :rtype: ``bool``
    '''

    return scheme.lower() in ('http', 'https')


def check_css_params(**validators):
    '''A decorator for validating arguments for function with specified
     validating function which returns True or False.

    :param validators: argument and it's validation function
    :raises ValueError: If validation fails.
    '''

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            arg_spec = inspect.getargspec(f)
            actual_args = dict(list(itertools.izip(arg_spec.args, args)) +
                               list(kwargs.iteritems()))
            dfs = arg_spec.defaults
            optional = dict(zip(arg_spec.args[-len(dfs):], dfs)) if dfs else {}

            for arg, func in validators.iteritems():
                if arg not in actual_args:
                    continue
                value = actual_args[arg]
                if arg in optional and optional[arg] == value:
                    continue
                if not func(value):
                    raise ValueError(
                        'Illegal argument: {}={}'.format(arg, value))
            return f(*args, **kwargs)
        return wrapper

    return decorator
