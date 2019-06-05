# coding: utf-8
import collections

from ._compat import OrderedDict, iteritems, string_types


__all__ = ['all_', 'not_', 'Var', 'Scope', 'DEFAULT_ROLE']

DEFAULT_ROLE = 'default'
"""A default role."""


def all_(role):
    """
    A matcher that always returns ``True``.

    :rtype: bool
    """
    return True


def not_(*roles):
    """
    Returns a matcher that returns ``True`` for all roles
    except those are listed as arguments.

    :rtype: callable
    """
    return lambda role: role not in roles


def construct_matcher(matcher):
    if callable(matcher):
        return matcher
    elif isinstance(matcher, string_types):
        return lambda r: r == matcher
    elif isinstance(matcher, collections.Iterable):
        choices = frozenset(matcher)
        return lambda r: r in choices
    else:
        raise ValueError(
            'Unknown matcher type {} ({!r}). Only callables, '
            'strings and iterables are supported.'.format(type(matcher), matcher)
        )


Resolution = collections.namedtuple('Resolution', ['value', 'role'])
"""
A resolution result, a :class:`~collections.namedtuple`.

.. attribute:: value

    A resolved value (the first element).

.. attribute:: role

    A role to be used for visiting nested objects (the second element).
"""


class Resolvable(object):
    """An interface that represents an object which value varies
    depending on a role.
    """

    def resolve(self, role):  # pragma: no cover
        """
        Returns a value for a given ``role``.

        :param str role: A role.
        :returns: A :class:`resolution <.Resolution>`.
        """
        raise NotImplementedError

    def iter_possible_values(self):  # pragma: no cover
        """Iterates over all possible values except ``None`` ones."""
        raise NotImplementedError


class Var(Resolvable):
    """
    A :class:`.Resolvable` implementation.

    :param values:
        A dictionary or a list of key-value pairs, where keys are matchers
        and values are corresponding values.

        Matchers are callables returning boolean values. Strings and
        iterables are also accepted and processed as follows:

        * A string ``s`` will be replaced with a lambda ``lambda r: r == s``;
        * An iterable ``i`` will be replaced with a lambda ``lambda r: r in i``.
    :type values: dict or list of pairs

    :param default:
        A value to return if all matchers returned ``False``.

    :param propagate:
        A matcher that determines which roles are to be propagated down
        to the nested objects. Default is :data:`all_` that matches
        all roles.
    :type propagate: callable, string or iterable
    """

    def __init__(self, values=None, default=None, propagate=all_):
        self._values = []
        if values is not None:
            values = iteritems(values) if isinstance(values, dict) else values
            for matcher, value in values:
                matcher = construct_matcher(matcher)
                self._values.append((matcher, value))
        self.default = default
        self._propagate = construct_matcher(propagate)

    @property
    def values(self):
        """A list of pairs (matcher, value)."""
        return self._values

    @property
    def propagate(self):
        """A matcher that determines which roles are to be propagated down
        to the nested objects.
        """
        return self._propagate

    def iter_possible_values(self):
        """
        Implements the :class:`.Resolvable` interface.

        Yields non-``None`` values from :attr:`values`.
        """
        return (v for _, v in self._values if v is not None)

    def resolve(self, role):
        """
        Implements the :class:`.Resolvable` interface.

        :param str role: A role.
        :returns:
            A :class:`resolution <.Resolution>`,

            which value is the first value which matcher returns ``True`` and
            the role is either a given ``role`` (if :attr:`propagate`` matcher
            returns ``True``) or :data:`.DEFAULT_ROLE` (otherwise).
        """
        for matcher, matcher_value in self._values:
            if matcher(role):
                value = matcher_value
                break
        else:
            value = self.default
        new_role = role if self._propagate(role) else DEFAULT_ROLE
        return Resolution(value, new_role)


class Scope(object):
    """
    A scope consists of a set of fields and a matcher.
    Fields can be added to a scope as attributes::

        scope = Scope('response')
        scope.name = StringField()
        scope.age = IntField()

    A scope can then be added to a :class:`~.Document`.
    During a document class construction process, fields of each of its scopes
    are added to the resulting class as :class:`variables <.Var>` which only
    resolve to fields when the matcher of the scope returns ``True``.

    If two fields with the same name are assigned to different document scopes,
    the matchers of the corresponding :class:`~.Var` will be the matchers of the
    scopes in order they were added to the class.

    :class:`.Scope` can also be used as a context manager. At the moment it
    does not do anything and only useful as a syntactic sugar -- to introduce
    an extra indentation level for the fields defined within the same scope.

    For example::

        class User(Document):
            with Scope('db_role') as db:
                db._id = StringField(required=True)
                db.version = StringField(required=True)
            with Scope('response_role') as db:
                db.version = IntField(required=True)

    Is an equivalent of::

        class User(Document):
            db._id = Var([
                ('db_role', StringField(required=True))
            ])
            db.version = Var([
                ('db_role', StringField(required=True))
                ('response_role', IntField(required=True))
            ])


    :param matcher: A matcher.
    :type matcher: callable, string or iterable

    .. attribute:: __field__

        An ordered dictionary of :class:`fields <.BaseField>`.

    .. attribute:: __matcher__

        A matcher.
    """

    def __init__(self, matcher):
        # names are chosen to avoid clashing with user field names
        super(Scope, self).__setattr__('__fields__', OrderedDict())
        super(Scope, self).__setattr__('__matcher__', matcher)

    def __getattr__(self, key):
        odict = super(Scope, self).__getattribute__('__fields__')
        if key in odict:
            return odict[key]
        return super(Scope, self).__getattribute__(key)

    def __setattr__(self, key, val):
        self.__fields__[key] = val

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
