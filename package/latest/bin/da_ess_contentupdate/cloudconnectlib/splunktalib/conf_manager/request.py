from .. import rest
from ..common import log


class ConfRequestException(Exception):
    pass


class ConfNotExistsException(ConfRequestException):
    pass


class ConfExistsException(ConfRequestException):
    pass


def content_request(uri, session_key, method, payload, err_msg):
    """
    :return: response content if successful otherwise raise
    ConfRequestException
    """

    resp, content = rest.splunkd_request(uri, session_key, method,
                                         data=payload, retry=3)
    if resp is None and content is None:
        return None

    if resp.status >= 200 and resp.status <= 204:
        return content
    else:
        msg = "%s, status=%s, reason=%s, detail=%s" % (
            err_msg, resp.status, resp.reason, content.decode('utf-8'))

        if not (method == "GET" and resp.status == 404):
            log.logger.error(msg)

        if resp.status == 404:
            raise ConfNotExistsException(msg)
        if resp.status == 409:
            raise ConfExistsException(msg)
        else:
            if content and "already exists" in content:
                raise ConfExistsException(msg)
            raise ConfRequestException(msg)
