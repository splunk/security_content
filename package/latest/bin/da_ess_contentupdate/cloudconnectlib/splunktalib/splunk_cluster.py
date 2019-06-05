from ..splunktalib import rest
from ..splunktalib.common import xml_dom_parser as xdp


def _do_rest(uri, session_key):
    resp, content = rest.splunkd_request(uri, session_key)
    if resp is None:
        return None

    if resp.status not in (200, 201):
        return None

    stanza_objs = xdp.parse_conf_xml_dom(content)
    if not stanza_objs:
        return None

    return stanza_objs[0]


class ServerInfo(object):

    def __init__(self, splunkd_uri, session_key):
        uri = "{}/services/server/info".format(splunkd_uri)
        server_info = _do_rest(uri, session_key)
        if server_info is None:
            raise Exception("Failed to init ServerInfo")

        self._server_info = server_info

    def is_captain(self):
        """
        :return: True if splunkd_uri is captain otherwise False
        """

        return "shc_captain" in self._server_info["server_roles"]

    def is_search_head(self):
        for sh in ("search_head", "cluster_search_head"):
            if sh in self._server_info["server_roles"]:
                return True
        return False

    def is_shc_member(self):
        server_roles = self._server_info['server_roles']
        return any(
            role in server_roles for role in ('shc_member', 'shc_captain')
        )

    def version(self):
        return self._server_info["version"]

    def to_dict(self):
        return self._server_info
