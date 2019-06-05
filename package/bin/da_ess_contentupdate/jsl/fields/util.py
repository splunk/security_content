# coding: utf-8
import re
import sre_constants

from ..roles import Resolvable


def validate_regex(regex):
    """
    :param str regex: A regular expression to validate.
    :raises: ValueError
    """
    try:
        re.compile(regex)
    except sre_constants.error as e:
        raise ValueError('Invalid regular expression: {0}'.format(e))


def validate(value_or_var, validator):
    if isinstance(value_or_var, Resolvable):
        for value in value_or_var.iter_possible_values():
            validator(value)
    else:
        validator(value_or_var)