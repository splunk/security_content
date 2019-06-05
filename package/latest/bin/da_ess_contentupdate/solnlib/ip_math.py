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
This module provides IP manipulate/calculation functionalities.
'''

import re


__all__ = ['ip2long',
           'long2ip',
           'cidr2long',
           'is_valid_mac',
           'is_valid_ip',
           'is_valid_mask',
           'is_valid_cidr',
           'expand_ip_range_to_cidr']


def ip2long(addr):
    '''Convert dotted IPv4 address to long.

    :param addr: Dotted IPv4 addrss.
    :type addr: ``string``
    :returns: Integer value of `addr`.
    :rtype: ``long``

    :raises ValueError: If `addr` is not a valid ip address.
    '''

    if is_valid_ip(addr):
        ip = [int(x) for x in addr.split('.')]
        return 16777216L * ip[0] + 65536 * ip[1] + 256 * ip[2] + ip[3]

    raise ValueError('Invalid ip address, should be a dotted IPv4 string.')


def long2ip(addr):
    '''Convert long to dotted IPv4 address.

    :param addr: Long IPv4 address.
    :type addr: ``(int, long)``
    :returns: Dotted IPv4 address.
    :rtype: ``string``
    '''

    if isinstance(addr, (int, long)):
        ip = long(addr)
        if ip >= 0 and ip < pow(2, 32):
            return '{}.{}.{}.{}'.format((ip >> 24) % 256, (ip >> 16) % 256,
                                        (ip >> 8) % 256, ip % 256)
        else:
            raise ValueError('Invalid ip address, not in valid ip range.')

    raise ValueError('Invalid ip address, should be an integer.')


def cidr2long(addr):
    '''Convert a CIDR to (ip_range_min, ip_range_max).

    :param addr: IPv4 CIDR.
    :type addr: ``string``
    :returns: Tuple of (ip_range_min, ip_range_max).
    :rtype: ``tuple``
    '''

    if is_valid_cidr(addr):
        subnet, mask = addr.split('/')
        range_min = ip2long(subnet)
        hosts = pow(2, 32 - long(mask)) - 1
        return (range_min, range_min + hosts)

    raise ValueError('Invalid CIDR address: %s.' % addr)


def is_valid_mac(addr):
    '''Validate a MAC address.

    :param addr: MAC address to validate.
    :type addr: ``string``
    :returns: True if is valid else False
    :rtype: ``bool``
    '''

    mac_rx = re.compile('^(([0-9A-Fa-f]{1,2}:){5}[0-9A-Fa-f]{1,2})$')
    try:
        return mac_rx.match(addr.strip())
    except AttributeError:
        # Value was not a string
        return False


def is_valid_ip(addr):
    '''Validate an IPV4 address.

    :param addr: IP address to validate.
    :type addr: ``string``
    :returns: True if is valid else False.
    :rtype: ``bool``
    '''

    ip_rx = re.compile(r'''
        ^(((
              [0-1]\d{2}                  # matches 000-199
            | 2[0-4]\d                    # matches 200-249
            | 25[0-5]                     # matches 250-255
            | \d{1,2}                     # matches 0-9, 00-99
        )\.){3})                          # 3 of the preceding stanzas
        ([0-1]\d{2}|2[0-4]\d|25[0-5]|\d{1,2})$     # final octet
    ''', re.VERBOSE)

    try:
        return ip_rx.match(addr.strip())
    except AttributeError:
        # Value was not a string
        return False


def is_valid_mask(mask):
    '''Validate an IPv4 netmask.

    :param mask: IPv4 netmask to validate.
    :type mask: ``integer``
    :returns: True if is valid else False
    :rtype: ``bool``
    '''

    try:
        return int(mask) >= 0 and int(mask) <= 32
    except ValueError:
        return False


def is_valid_cidr(addr):
    '''Validate an IPv4 CIDR.

    :param addr: IPv4 CIDR to validate.
    :type addr: ``string``
    :returns: True if is valid else False
    :rtype: ``bool``
    '''

    try:
        subnet, mask = addr.split('/', 1)
        if is_valid_ip(subnet) and is_valid_mask(mask):
            subnet_long = ip2long(subnet)
            mask = int(mask)

            # Use floor division to get the number of valid bits that can
            # be specified in the subnet. For instance,
            # 1.1.1.1/24 is not valid; should be 1.1.1.0/24
            invalid_bits = pow(2, ((32 - mask) // 8) * 8) - 1

            return not subnet_long & invalid_bits

        return False
    except (AttributeError, ValueError):
        # Not a string in CIDR format.
        return False


def expand_ip_range_to_cidr(ip_range, clean_single_ips=False):
    '''Convert ip_range to a list of CIDR addresses.

    It will return a minimal list of CIDR addresses covering the same IPv4
    range as the input range, inclusive. The input range MUST be one of the
    formats shown below, representing a range a.b.c.d-e.f.g.h where a.b.c.d
    < e.f.g.h. If this is not true, ValueError will be raised.

    :param ip_range: An IPv4 address range in (range_start, range_end) format.
    :type ip_range: ``tuple``
    :param clean_single_ips: (optional) If True, remove '/32' suffix from
        single IPs, default is False.
    :type clean_single_ips: ``bool``
    :returns: A list of strings 'a.b.c.d[/N]' where 0 <= N <= 32.
    :rtype: ``list``
    '''

    # The output list of subnets.
    subnets = []

    RANGE_MIN = 0
    RANGE_MAX = pow(2, 32)

    range_start, range_end = ip_range

    if range_start <= range_end and range_start >= RANGE_MIN and \
       range_end <= RANGE_MAX:

        # Begin range-to-CIDR algorithm.
        #
        # This algorithm is based on longest-common-prefix matching. Each
        # subnet consists of a binary prefix of (32-N) digits, to which are
        # appended all binary integers up to N digits in length.
        #
        # 0. Convert range_start and range_end to long integers.
        # 1. Flip all of the 0 bits at the end of the binary representation of
        #    range_start to 1. The delta between range_start and last_in_subnet
        #    will then represent a maximal block of IP addresses up to the next
        #    CIDR block. The next CIDR block will begin with a different prefix
        #    one bit shorter in length.
        # 2. If the last_in_subnet value is greater than the range_end value,
        #    our subnet is too large. Calculate the largest subnet (power of 2)
        #    that will fit into the range by using the bit_length() of the
        #    difference between range_start and range_end, plus 1. This will
        #    give us the correct value of last_in_subnet.
        # 3. Emit the current subnet.
        # 4. Set range_start to the value of last_in_subnet plus 1, and repeat.
        # 5. Upon exiting the loop, range_start and range_end will exist in one
        #    of the following relations:
        #    a. range_start > range_end
        #       This means that the range_end matched our final subnet exactly,
        #       and no more coverage is needed.
        #    b. range_start == range_end
        #       This means that the subnet left one 'dangling' IP, which should
        #       be covered via a /32 subnet.
        #
        # Example:
        #
        #    Given the following
        #
        #      range_start = 10.10.10.10, rangeEnd = 10.10.10.20
        #
        #    we have:
        #
        #      bin(range_start) = '0b1010000010100000101000001010'
        #      bin(range_end)   = '0b1010000010100000101000010100'
        #
        #    This yields the following set of CIDRS covering the
        #    addresses shown in binary, with the common prefix
        #    marked by a pipe  character:
        #
        #    10.10.10.10/31                 |
        #      '0b1010000010100000101000001010'    <- '0' suffix
        #      '0b1010000010100000101000001011'    <- '1' suffix
        #    10.10.10.12/30                |
        #      '0b1010000010100000101000001100'    <- '00' suffix
        #      '0b1010000010100000101000001101'    <- '01' suffix
        #      '0b1010000010100000101000001110'    <- '10' suffix
        #      '0b1010000010100000101000001111'    <- '11' suffix
        #    10.10.10.16/30              X |
        #      '0b1010000010100000101000010000'
        #      '0b1010000010100000101000010001'
        #      '0b1010000010100000101000010010'
        #      '0b1010000010100000101000010011'
        #    10.10.10.20/32                  |
        #      '0b1010000010100000101000010100'
        #
        #    Note that the subnet 10.10.10.16/30 would have been 'reduced'
        #    from an originally calculated mask of /29. The 'X' represents
        #    the original guess.

        while range_start < range_end:
            # Flip the rightmost zero bits; this will be our initial subnet
            # guess. See Hacker's Delight pg. 11.
            last_in_subnet = range_start | (range_start - 1)

            # Handle rollover when range_start is '0.0.0.0'
            if last_in_subnet == -1:
                last_in_subnet = 2 ** 32 - 1

            if last_in_subnet > range_end:
                # reduce to the largest possible size and retry
                diff = range_end - range_start + 1
                last_in_subnet = range_start + 2 ** (diff.bit_length() - 1) - 1

            mask = 32 - (last_in_subnet - range_start).bit_length()
            if clean_single_ips and mask == 32:
                subnets.append(long2ip(range_start))
            else:
                subnets.append('/'.join([long2ip(range_start), str(mask)]))

            range_start = last_in_subnet + 1

        if range_start > range_end:
            pass
        elif range_start == range_end:
            # Add the last address
            if clean_single_ips:
                subnets.append(long2ip(range_start))
            else:
                subnets.append(long2ip(range_start) + '/32')
        else:
            # This should never happen due to the exit condition on the above
            # while loop.
            raise ValueError('Subnet calculation failed unexpectedly.')

    else:
        # Invalid IP range.
        raise ValueError(
            'Invalid IP range specified (perhaps reversed).')

    return sorted(subnets, key=lambda x: x.split('/')[1])
