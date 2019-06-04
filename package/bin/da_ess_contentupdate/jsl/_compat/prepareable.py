import sys
import inspect
from functools import wraps

from . import IS_PY3


class Prepareable(type):
    # this code is taken from https://gist.github.com/DasIch/5562625 with minor fixes
    if not IS_PY3:
        def __new__(cls, name, bases, attributes):
            try:
                constructor = attributes["__new__"]
            except KeyError:
                return type.__new__(cls, name, bases, attributes)

            def preparing_constructor(cls, name, bases, attributes):
                try:
                    cls.__prepare__
                except AttributeError:
                    return constructor(cls, name, bases, attributes)
                namespace = cls.__prepare__(name, bases)
                defining_frame = sys._getframe(1)
                for constant in reversed(defining_frame.f_code.co_consts):
                    if inspect.iscode(constant) and constant.co_name == name:
                        def get_index(attribute_name, _names=constant.co_names):
                            try:
                                return _names.index(attribute_name)
                            except ValueError:
                                return 0
                        break
                else:
                    return constructor(cls, name, bases, attributes)

                by_appearance = sorted(
                    attributes.items(), key=lambda item: get_index(item[0])
                )
                for key, value in by_appearance:
                    namespace[key] = value
                return constructor(cls, name, bases, namespace)
            attributes["__new__"] = wraps(constructor)(preparing_constructor)
            return type.__new__(cls, name, bases, attributes)