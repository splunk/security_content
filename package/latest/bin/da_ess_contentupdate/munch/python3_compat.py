import sys

_PY2 = (sys.version_info < (3,0))

identity = lambda x : x

# u('string') replaces the forwards-incompatible u'string'
if _PY2:
    import codecs
    def u(string):
        return codecs.unicode_escape_decode(string)[0]
else:
    u = identity

# dict.iteritems(), dict.iterkeys() is also incompatible
if _PY2:
    iteritems = dict.iteritems
    iterkeys = dict.iterkeys
else:
    iteritems = dict.items
    iterkeys  = dict.keys

