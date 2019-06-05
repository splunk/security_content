# coding: utf-8
from ._compat import itervalues


_documents_registry = {}


def get_document(name, module=None):
    if module:
        name = '{0}.{1}'.format(module, name)
    return _documents_registry[name]


def put_document(name, document_cls, module=None):
    if module:
        name = '{0}.{1}'.format(module, name)
    _documents_registry[name] = document_cls


def remove_document(name, module=None):
    if module:
        name = '{0}.{1}'.format(module, name)
    del _documents_registry[name]


def iter_documents():
    return itervalues(_documents_registry)


def clear():
    _documents_registry.clear()