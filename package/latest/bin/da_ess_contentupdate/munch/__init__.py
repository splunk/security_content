#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Munch is a subclass of dict with attribute-style access.

    >>> b = Munch()
    >>> b.hello = 'world'
    >>> b.hello
    'world'
    >>> b['hello'] += "!"
    >>> b.hello
    'world!'
    >>> b.foo = Munch(lol=True)
    >>> b.foo.lol
    True
    >>> b.foo is b['foo']
    True

    It is safe to import * from this module:

        __all__ = ('Munch', 'munchify','unmunchify')

    un/munchify provide dictionary conversion; Munches can also be
    converted via Munch.to/fromDict().
"""

__version__ = '2.0.4'
VERSION = tuple(map(int, __version__.split('.')))

__all__ = ('Munch', 'munchify','unmunchify',)

from .python3_compat import *

class Munch(dict):
    """ A dictionary that provides attribute-style access.

        >>> b = Munch()
        >>> b.hello = 'world'
        >>> b.hello
        'world'
        >>> b['hello'] += "!"
        >>> b.hello
        'world!'
        >>> b.foo = Munch(lol=True)
        >>> b.foo.lol
        True
        >>> b.foo is b['foo']
        True

        A Munch is a subclass of dict; it supports all the methods a dict does...

        >>> sorted(b.keys())
        ['foo', 'hello']

        Including update()...

        >>> b.update({ 'ponies': 'are pretty!' }, hello=42)
        >>> print (repr(b))
        Munch({'ponies': 'are pretty!', 'foo': Munch({'lol': True}), 'hello': 42})

        As well as iteration...

        >>> sorted([ (k,b[k]) for k in b ])
        [('foo', Munch({'lol': True})), ('hello', 42), ('ponies', 'are pretty!')]

        And "splats".

        >>> "The {knights} who say {ni}!".format(**Munch(knights='lolcats', ni='can haz'))
        'The lolcats who say can haz!'

        See unmunchify/Munch.toDict, munchify/Munch.fromDict for notes about conversion.
    """

    def __contains__(self, k):
        """ >>> b = Munch(ponies='are pretty!')
            >>> 'ponies' in b
            True
            >>> 'foo' in b
            False
            >>> b['foo'] = 42
            >>> 'foo' in b
            True
            >>> b.hello = 'hai'
            >>> 'hello' in b
            True
            >>> b[None] = 123
            >>> None in b
            True
            >>> b[False] = 456
            >>> False in b
            True
        """
        try:
            return dict.__contains__(self, k) or hasattr(self, k)
        except:
            return False

    # only called if k not found in normal places
    def __getattr__(self, k):
        """ Gets key if it exists, otherwise throws AttributeError.

            nb. __getattr__ is only called if key is not found in normal places.

            >>> b = Munch(bar='baz', lol={})
            >>> b.foo
            Traceback (most recent call last):
                ...
            AttributeError: foo

            >>> b.bar
            'baz'
            >>> getattr(b, 'bar')
            'baz'
            >>> b['bar']
            'baz'

            >>> b.lol is b['lol']
            True
            >>> b.lol is getattr(b, 'lol')
            True
        """
        try:
            # Throws exception if not in prototype chain
            return object.__getattribute__(self, k)
        except AttributeError:
            try:
                return self[k]
            except KeyError:
                raise AttributeError(k)

    def __setattr__(self, k, v):
        """ Sets attribute k if it exists, otherwise sets key k. A KeyError
            raised by set-item (only likely if you subclass Munch) will
            propagate as an AttributeError instead.

            >>> b = Munch(foo='bar', this_is='useful when subclassing')
            >>> hasattr(b.values, '__call__')
            True
            >>> b.values = 'uh oh'
            >>> b.values
            'uh oh'
            >>> b['values']
            Traceback (most recent call last):
                ...
            KeyError: 'values'
        """
        try:
            # Throws exception if not in prototype chain
            object.__getattribute__(self, k)
        except AttributeError:
            try:
                self[k] = v
            except:
                raise AttributeError(k)
        else:
            object.__setattr__(self, k, v)

    def __delattr__(self, k):
        """ Deletes attribute k if it exists, otherwise deletes key k. A KeyError
            raised by deleting the key--such as when the key is missing--will
            propagate as an AttributeError instead.

            >>> b = Munch(lol=42)
            >>> del b.lol
            >>> b.lol
            Traceback (most recent call last):
                ...
            AttributeError: lol
        """
        try:
            # Throws exception if not in prototype chain
            object.__getattribute__(self, k)
        except AttributeError:
            try:
                del self[k]
            except KeyError:
                raise AttributeError(k)
        else:
            object.__delattr__(self, k)

    def toDict(self):
        """ Recursively converts a munch back into a dictionary.

            >>> b = Munch(foo=Munch(lol=True), hello=42, ponies='are pretty!')
            >>> sorted(b.toDict().items())
            [('foo', {'lol': True}), ('hello', 42), ('ponies', 'are pretty!')]

            See unmunchify for more info.
        """
        return unmunchify(self)

    def __repr__(self):
        """ Invertible* string-form of a Munch.

            >>> b = Munch(foo=Munch(lol=True), hello=42, ponies='are pretty!')
            >>> print (repr(b))
            Munch({'ponies': 'are pretty!', 'foo': Munch({'lol': True}), 'hello': 42})
            >>> eval(repr(b))
            Munch({'ponies': 'are pretty!', 'foo': Munch({'lol': True}), 'hello': 42})

            >>> with_spaces = Munch({1: 2, 'a b': 9, 'c': Munch({'simple': 5})})
            >>> print (repr(with_spaces))
            Munch({'a b': 9, 1: 2, 'c': Munch({'simple': 5})})
            >>> eval(repr(with_spaces))
            Munch({'a b': 9, 1: 2, 'c': Munch({'simple': 5})})

            (*) Invertible so long as collection contents are each repr-invertible.
        """
        return '%s(%s)' % (self.__class__.__name__, dict.__repr__(self))



    def __dir__(self):
        return list(iterkeys(self))

    __members__ = __dir__ # for python2.x compatibility

    @staticmethod
    def fromDict(d):
        """ Recursively transforms a dictionary into a Munch via copy.

            >>> b = Munch.fromDict({'urmom': {'sez': {'what': 'what'}}})
            >>> b.urmom.sez.what
            'what'

            See munchify for more info.
        """
        return munchify(d)



# While we could convert abstract types like Mapping or Iterable, I think
# munchify is more likely to "do what you mean" if it is conservative about
# casting (ex: isinstance(str,Iterable) == True ).
#
# Should you disagree, it is not difficult to duplicate this function with
# more aggressive coercion to suit your own purposes.

def munchify(x):
    """ Recursively transforms a dictionary into a Munch via copy.

        >>> b = munchify({'urmom': {'sez': {'what': 'what'}}})
        >>> b.urmom.sez.what
        'what'

        munchify can handle intermediary dicts, lists and tuples (as well as
        their subclasses), but ymmv on custom datatypes.

        >>> b = munchify({ 'lol': ('cats', {'hah':'i win again'}),
        ...         'hello': [{'french':'salut', 'german':'hallo'}] })
        >>> b.hello[0].french
        'salut'
        >>> b.lol[1].hah
        'i win again'

        nb. As dicts are not hashable, they cannot be nested in sets/frozensets.
    """
    if isinstance(x, dict):
        return Munch( (k, munchify(v)) for k,v in iteritems(x) )
    elif isinstance(x, (list, tuple)):
        return type(x)( munchify(v) for v in x )
    else:
        return x

def unmunchify(x):
    """ Recursively converts a Munch into a dictionary.

        >>> b = Munch(foo=Munch(lol=True), hello=42, ponies='are pretty!')
        >>> sorted(unmunchify(b).items())
        [('foo', {'lol': True}), ('hello', 42), ('ponies', 'are pretty!')]

        unmunchify will handle intermediary dicts, lists and tuples (as well as
        their subclasses), but ymmv on custom datatypes.

        >>> b = Munch(foo=['bar', Munch(lol=True)], hello=42,
        ...         ponies=('are pretty!', Munch(lies='are trouble!')))
        >>> sorted(unmunchify(b).items()) #doctest: +NORMALIZE_WHITESPACE
        [('foo', ['bar', {'lol': True}]), ('hello', 42), ('ponies', ('are pretty!', {'lies': 'are trouble!'}))]

        nb. As dicts are not hashable, they cannot be nested in sets/frozensets.
    """
    if isinstance(x, dict):
        return dict( (k, unmunchify(v)) for k,v in iteritems(x) )
    elif isinstance(x, (list, tuple)):
        return type(x)( unmunchify(v) for v in x )
    else:
        return x


### Serialization

try:
    try:
        import json
    except ImportError:
        import simplejson as json

    def toJSON(self, **options):
        """ Serializes this Munch to JSON. Accepts the same keyword options as `json.dumps()`.

            >>> b = Munch(foo=Munch(lol=True), hello=42, ponies='are pretty!')
            >>> json.dumps(b) == b.toJSON()
            True
        """
        return json.dumps(self, **options)

    Munch.toJSON = toJSON

except ImportError:
    pass




try:
    # Attempt to register ourself with PyYAML as a representer
    import yaml
    from yaml.representer import Representer, SafeRepresenter

    def from_yaml(loader, node):
        """ PyYAML support for Munches using the tag `!munch` and `!munch.Munch`.

            >>> import yaml
            >>> yaml.load('''
            ... Flow style: !munch.Munch { Clark: Evans, Brian: Ingerson, Oren: Ben-Kiki }
            ... Block style: !munch
            ...   Clark : Evans
            ...   Brian : Ingerson
            ...   Oren  : Ben-Kiki
            ... ''') #doctest: +NORMALIZE_WHITESPACE
            {'Flow style': Munch(Brian='Ingerson', Clark='Evans', Oren='Ben-Kiki'),
             'Block style': Munch(Brian='Ingerson', Clark='Evans', Oren='Ben-Kiki')}

            This module registers itself automatically to cover both Munch and any
            subclasses. Should you want to customize the representation of a subclass,
            simply register it with PyYAML yourself.
        """
        data = Munch()
        yield data
        value = loader.construct_mapping(node)
        data.update(value)


    def to_yaml_safe(dumper, data):
        """ Converts Munch to a normal mapping node, making it appear as a
            dict in the YAML output.

            >>> b = Munch(foo=['bar', Munch(lol=True)], hello=42)
            >>> import yaml
            >>> yaml.safe_dump(b, default_flow_style=True)
            '{foo: [bar, {lol: true}], hello: 42}\\n'
        """
        return dumper.represent_dict(data)

    def to_yaml(dumper, data):
        """ Converts Munch to a representation node.

            >>> b = Munch(foo=['bar', Munch(lol=True)], hello=42)
            >>> import yaml
            >>> yaml.dump(b, default_flow_style=True)
            '!munch.Munch {foo: [bar, !munch.Munch {lol: true}], hello: 42}\\n'
        """
        return dumper.represent_mapping(u('!munch.Munch'), data)


    yaml.add_constructor(u('!munch'), from_yaml)
    yaml.add_constructor(u('!munch.Munch'), from_yaml)

    SafeRepresenter.add_representer(Munch, to_yaml_safe)
    SafeRepresenter.add_multi_representer(Munch, to_yaml_safe)

    Representer.add_representer(Munch, to_yaml)
    Representer.add_multi_representer(Munch, to_yaml)


    # Instance methods for YAML conversion
    def toYAML(self, **options):
        """ Serializes this Munch to YAML, using `yaml.safe_dump()` if
            no `Dumper` is provided. See the PyYAML documentation for more info.

            >>> b = Munch(foo=['bar', Munch(lol=True)], hello=42)
            >>> import yaml
            >>> yaml.safe_dump(b, default_flow_style=True)
            '{foo: [bar, {lol: true}], hello: 42}\\n'
            >>> b.toYAML(default_flow_style=True)
            '{foo: [bar, {lol: true}], hello: 42}\\n'
            >>> yaml.dump(b, default_flow_style=True)
            '!munch.Munch {foo: [bar, !munch.Munch {lol: true}], hello: 42}\\n'
            >>> b.toYAML(Dumper=yaml.Dumper, default_flow_style=True)
            '!munch.Munch {foo: [bar, !munch.Munch {lol: true}], hello: 42}\\n'
        """
        opts = dict(indent=4, default_flow_style=False)
        opts.update(options)
        if 'Dumper' not in opts:
            return yaml.safe_dump(self, **opts)
        else:
            return yaml.dump(self, **opts)

    def fromYAML(*args, **kwargs):
        return munchify( yaml.load(*args, **kwargs) )

    Munch.toYAML = toYAML
    Munch.fromYAML = staticmethod(fromYAML)

except ImportError:
    pass


if __name__ == "__main__":
    import doctest
    doctest.testmod()

