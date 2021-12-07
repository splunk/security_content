import abc

from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType


class SecurityContentObject(abc.ABC):
    type: SecurityContentType
