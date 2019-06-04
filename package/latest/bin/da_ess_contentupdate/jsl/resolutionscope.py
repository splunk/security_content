# coding: utf-8
from ._compat import urljoin, urldefrag


class ResolutionScope(object):
    """
    An utility class to help with translating ``id`` attributes of
    :class:`fields <.BaseSchemaField>` into JSON schema ``"id"`` properties.

    :param str base:
        A URI, a resolution scope of the outermost schema.
    :param str current:
        A URI, a resolution scope of the current schema.
    :param str output:
        A URI, an output part (expressed by parent schema id properties) scope of
        the current schema.
    """
    def __init__(self, base='', current='', output=''):
        self._base, _ = urldefrag(base)
        self._current, _ = urldefrag(current)
        self._output, _ = urldefrag(output)

    base = property(lambda self: self._base)
    """A resolution scope of the outermost schema."""
    current = property(lambda self: self._current)
    """A resolution scope of the current schema."""
    output = property(lambda self: self._output)
    """An output part (expressed by parent schema id properties) scope of
    the current schema.
    """

    def __repr__(self):
        return 'ResolutionScope(\n  base={0},\n  current={1},\n  output={2}\n)'.format(
            self._base, self._current, self._output)

    def replace(self, current=None, output=None):
        """Returns a copy of the scope with the ``current`` and ``output``
        scopes replaced.
        """
        return ResolutionScope(
            base=self._base,
            current=self._current if current is None else current,
            output=self._output if output is None else output
        )

    def alter(self, field_id):
        """Returns a pair, where the first element is the identifier to be used
        as a value for the ``"id"`` JSON schema field and the second is
        a new :class:`.ResolutionScope` to be used when visiting the nested fields
        of the field with id ``field_id``.

        :rtype: (str, :class:`.ResolutionScope`)
        """
        new_current = urljoin(self._current or self._base, field_id)
        if new_current.startswith(self._output):
            schema_id = new_current[len(self._output):]
        else:
            schema_id = new_current
        return schema_id, self.replace(current=new_current, output=new_current)

    def create_ref(self, definition_id):
        """Returns a reference (``{"$ref": ...}``) relative to the base scope."""
        ref = '{0}#/definitions/{1}'.format(
            self._base if self._current and self._base != self._current else '',
            definition_id
        )
        return {'$ref': ref}


EMPTY_SCOPE = ResolutionScope()
"""An empty :class:`.ResolutionScope`."""
