
from __future__ import absolute_import

from .eai import RestEAI

__all__ = ['RestEntity']


class RestEntity(object):

    def __init__(self, name, content, model, user, app, acl=None):
        self.name = name
        self.content = content
        self.model = model
        self._eai = RestEAI(self.model, user, app, acl)

    @property
    def eai(self):
        return self._eai
