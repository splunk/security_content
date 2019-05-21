# coding: utf-8
"""
Compatibility utils for Python 2 & 3.
"""
import sys


IS_PY3 = sys.version_info[0] == 3
string_types = (str, ) if IS_PY3 else (basestring, )
text_type = str if IS_PY3 else unicode
_identity = lambda x: x


if IS_PY3:
    from urllib.parse import urljoin, urlunsplit, urlsplit

    implements_to_string = _identity
else:
    from urlparse import urljoin, urlunsplit, urlsplit

    def implements_to_string(cls):
        cls.__unicode__ = cls.__str__
        cls.__str__ = lambda x: x.__unicode__().encode('utf-8')
        return cls


def iterkeys(obj, **kwargs):
    """Iterate over dict keys in Python 2 & 3."""
    return (obj.iterkeys(**kwargs)
            if hasattr(obj, 'iterkeys')
            else iter(obj.keys(**kwargs)))


def iteritems(obj, **kwargs):
    """Iterate over dict items in Python 2 & 3."""
    return (obj.iteritems(**kwargs)
            if hasattr(obj, 'iteritems')
            else iter(obj.items(**kwargs)))


def itervalues(obj, **kwargs):
    """Iterate over dict values in Python 2 & 3."""
    return (obj.itervalues(**kwargs)
            if hasattr(obj, 'itervalues')
            else iter(obj.values(**kwargs)))


def with_metaclass(meta, *bases):
    """Create a base class with a metaclass.

    Function copied from `six <https://bitbucket.org/gutworth/six>`_ package.
    """
    # This requires a bit of explanation: the basic idea is to make a dummy
    # metaclass for one level of class instantiation that replaces itself with
    # the actual metaclass.
    class metaclass(meta):
        def __new__(cls, name, this_bases, d):
            return meta(name, bases, d)
    return type.__new__(metaclass, 'temporary_class', (), {})


# On python < 3.3 fragments are not handled properly with unknown schemes

def urldefrag(url):
    if "#" in url:
        s, n, p, q, frag = urlsplit(url)
        defrag = urlunsplit((s, n, p, q, ''))
    else:
        defrag = url
        frag = ''
    return defrag, frag


try:
    from collections import OrderedDict
except ImportError:
    from .ordereddict import OrderedDict


from .prepareable import Prepareable