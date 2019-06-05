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
The Splunk Software Development Kit for Solutions.
'''

from . import (
    acl,
    api_documenter,
    compression,
    conf_manager,
    credentials,
    file_monitor,
    hec_config,
    ip_math,
    log,
    metadata,
    net_utils,
    orphan_process_monitor,
    pattern,
    server_info,
    splunk_rest_client,
    splunkenv,
    time_parser,
    timer_queue,
    user_access,
    utils,
)

__all__ = ['acl',
           'api_documenter',
           'compression',
           'conf_manager',
           'credentials',
           'file_monitor',
           'hec_config',
           'ip_math',
           'log',
           'metadata',
           'net_utils',
           'orphan_process_monitor',
           'pattern',
           'server_info',
           'splunk_rest_client',
           'splunkenv',
           'time_parser',
           'timer_queue',
           'user_access',
           'utils']

__version__ = '1.0.17-dev.157'
