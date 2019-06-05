# coding: utf-8
"""
JSL
===
A Python DSL for describing JSON schemas.
See http://jsl.rtfd.org/ for documentation.
:copyright: (c) 2016 Anton Romanovich
:license: BSD
"""

__title__ = 'JSL'
__author__ = 'Anton Romanovich'
__license__ = 'BSD'
__copyright__ = 'Copyright 2016 Anton Romanovich'
__version__ = '0.2.4'
__version_info__ = tuple(int(i) for i in __version__.split('.'))


from .document import Document, ALL_OF, INLINE, ANY_OF, ONE_OF
from .fields import *
from .roles import *
from .exceptions import SchemaGenerationException
