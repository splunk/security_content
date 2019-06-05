# coding: utf-8
import collections
import contextlib

from .roles import DEFAULT_ROLE
from ._compat import implements_to_string, text_type


@contextlib.contextmanager
def processing(step):
    """
    A context manager. If an :class:`SchemaGenerationException` occurs within
    its nested code block, it adds ``step`` to it and reraises.
    """
    try:
        yield
    except SchemaGenerationException as e:
        e.steps.appendleft(step)
        raise


class Step(object):
    """A step of the schema generation process that caused the error."""

    def __init__(self, entity, role=DEFAULT_ROLE):
        """
        :param entity: An entity being processed.
        :param str role: A current role.
        """
        #: An entity being processed.
        self.entity = entity
        #: A current role.
        self.role = role

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

    def __repr__(self):
        return '{0}({1!r}, role={2})'.format(
            self.__class__.__name__, self.entity, self.role)


@implements_to_string
class DocumentStep(Step):
    """
    A step of processing a :class:`document <.Document>`.

    :type entity: subclass of :class:`~.Document`
    """

    def __str__(self):
        return self.entity.__name__


@implements_to_string
class FieldStep(Step):
    """
    A step of processing a :class:`field <.BaseField>`.

    :type entity: instance of :class:`~.BaseField`
    """

    def __str__(self):
        return self.entity.__class__.__name__


@implements_to_string
class AttributeStep(Step):
    """
    A step of processing an attribute of a field.

    ``entity`` is the name of an attribute
    (e.g., ``"properties"``, ``"additional_properties"``, etc.)

    :type entity: str
    """

    def __str__(self):
        return self.entity


@implements_to_string
class ItemStep(Step):
    """
    A step of processing an item of an attribute.

    ``entity`` is either a key or an index (e.g., it can be ``"created_at"``
    if the current attribute is ``properties`` of a :class:`~.DictField` or
    ``0`` if the current attribute is ``items`` of a :class:`~.ArrayField`).

    :type entity: str or int
    """

    def __str__(self):
        return repr(self.entity)


@implements_to_string
class SchemaGenerationException(Exception):
    """
    Raised when a valid JSON schema can not be generated from a JSL object.

    Examples of such situation are the following:

    * A :class:`variable <.Var>` resolves to an integer but a
      :class:`.BaseField` expected;
    * All choices of :class:`.OneOfField` are variables and all resolve to ``None``.

    Note: this error can only happen if variables are used in a document or field
    description.

    :param str message: A message.
    """

    def __init__(self, message):
        self.message = message
        """A message."""
        self.steps = collections.deque()
        """
        A deque of :class:`steps <.Step>`, ordered from the first (the least specific)
        to the last (the most specific).
        """

    def _format_steps(self):
        if not self.steps:
            return ''
        parts = []
        steps = iter(self.steps)
        parts.append(str(next(steps)))
        for step in steps:
            if isinstance(step, (DocumentStep, FieldStep)):
                parts.append(' -> {0}'.format(step))
            elif isinstance(step, AttributeStep):
                parts.append('.{0}'.format(step))
            elif isinstance(step, ItemStep):
                parts.append('[{0}]'.format(step))
        return ''.join(parts)

    def __str__(self):
        rv = text_type(self.message)
        steps = self._format_steps()
        if steps:
            rv += u'\nSteps: {0}'.format(steps)
        return rv
