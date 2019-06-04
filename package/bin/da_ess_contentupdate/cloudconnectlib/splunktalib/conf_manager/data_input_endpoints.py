from .request import content_request
from ..common import util
from ..common import xml_dom_parser as xdp

INPUT_ENDPOINT = "%s/servicesNS/%s/%s/data/inputs/%s"


def _input_endpoint_ns(uri, owner, app, input_type):
    return INPUT_ENDPOINT % (uri, owner, app, input_type)


def reload_data_input(splunkd_uri, session_key, owner, app_name,
                      input_type, throw=False):
    """
    :param splunkd_uri: splunkd uri, e.g. https://127.0.0.1:8089
    :param session_key: splunkd session key
    :param owner: the owner (ACL user), e.g. "-", "nobody"
    :param app_name: the app"s name, e.g. "Splunk_TA_aws"
    :param input_type: name of the input type.
                       if it is a script input, the input is "script",
                       for modinput, say snow, the input is "snow"
    """

    uri = _input_endpoint_ns(splunkd_uri, owner, app_name, input_type)
    uri += "/_reload"
    msg = "Failed to reload data input in app=%s: %s" % (app_name, input_type)
    try:
        content_request(uri, session_key, "GET", None, msg)
    except Exception:
        if throw:
            raise


def create_data_input(splunkd_uri, session_key, owner, app_name, input_type,
                      name, key_values):
    """
    :param splunkd_uri: splunkd uri, e.g. https://127.0.0.1:8089
    :param session_key: splunkd session key
    :param owner: the owner (ACL user), e.g. "-", "nobody"
    :param app_name: the app"s name, e.g. "Splunk_TA_aws"
    :param input_type: name of the input type.
                       if it is a script input, the input is "script",
                       for modinput, say snow, the input is "snow"
    :param name: The name of the input stanza to create.
                 i.e. stanza [<input_type>://<name>] will be created.
    :param key_values: a K-V dict of details in the data input stanza.
    :return: None on success else raise exception
    """

    key_values["name"] = unicode(name).encode('utf-8')
    uri = _input_endpoint_ns(splunkd_uri, owner, app_name, input_type)
    msg = "Failed to create data input in app=%s: %s://%s" % (
        app_name, input_type, name)
    content_request(uri, session_key, "POST", key_values, msg)


def get_data_input(splunkd_uri, session_key, owner, app_name, input_type,
                   name=None):
    """
    :param splunkd_uri: splunkd uri, e.g. https://127.0.0.1:8089
    :param session_key: splunkd session key
    :param owner: the owner (ACL user), e.g. "-", "nobody"
    :param app_name: the app"s name, e.g. "Splunk_TA_aws"
    :param input_type: name of the input type.
                       if it is a script input, the input is "script",
                       for modinput, say snow, the input is "snow"
    :param name: The name of the input stanza to create.
                 i.e. stanza [<input_type>://<name>] will be deleted.
    :return: a list of stanzas in the input type, including metadata
    """

    uri = _input_endpoint_ns(splunkd_uri, owner, app_name, input_type)
    if name:
        uri += "/" + util.format_stanza_name(name)

    # get all the stanzas at one time
    uri += "?count=0&offset=0"

    msg = "Failed to get data input in app=%s: %s://%s" % (
        app_name, input_type, name if name else name)
    content = content_request(uri, session_key, "GET", None, msg)
    return xdp.parse_conf_xml_dom(content)


def update_data_input(splunkd_uri, session_key, owner, app_name, input_type,
                      name, key_values):
    """
    :param splunkd_uri: splunkd uri, e.g. https://127.0.0.1:8089
    :param session_key: splunkd session key
    :param owner: the owner (ACL user), e.g. "-", "nobody"
    :param app_name: the app"s name, e.g. "Splunk_TA_aws"
    :param input_type: name of the input type.
                       if it is a script input, the input is "script",
                       for modinput, say snow, the input is "snow"
    :param name: The name of the input stanza to create.
                 i.e. stanza [<input_type>://<name>] will be updated.
    :param key_values: a K-V dict of details in the data input stanza.
    :return: raise exception when failure
    """

    if "name" in key_values:
        del key_values["name"]
    uri = _input_endpoint_ns(splunkd_uri, owner, app_name, input_type)
    uri += "/" + util.format_stanza_name(name)
    msg = "Failed to update data input in app=%s: %s://%s" % (
        app_name, input_type, name)
    content_request(uri, session_key, "POST", key_values, msg)


def delete_data_input(splunkd_uri, session_key, owner, app_name, input_type,
                      name):
    """
    :param splunkd_uri: splunkd uri, e.g. https://127.0.0.1:8089
    :param session_key: splunkd session key
    :param owner: the owner (ACL user), e.g. "-", "nobody"
    :param app_name: the app"s name, e.g. "Splunk_TA_aws"
    :param input_type: name of the input type.
                       if it is a script input, the input is "script",
                       for modinput, say snow, the input is "snow"
    :param name: The name of the input stanza to create.
                 i.e. stanza [<input_type>://<name>] will be deleted.
    :return raise exception when failed
    """

    uri = _input_endpoint_ns(splunkd_uri, owner, app_name, input_type)
    uri += "/" + util.format_stanza_name(name)
    msg = "Failed to delete data input in app=%s: %s://%s" % (
        app_name, input_type, name)
    content_request(uri, session_key, "DELETE", None, msg)


def operate_data_input(splunkd_uri, session_key, owner, app_name,
                       input_type, name, operation):
    """
    :param splunkd_uri: splunkd uri, e.g. https://127.0.0.1:8089
    :param session_key: splunkd session key
    :param owner: the owner (ACL user), e.g. "-", "nobody"
    :param app_name: the app"s name, e.g. "Splunk_TA_aws"
    :param input_type: name of the input type.
                       if it is a script input, the input is "script",
                       for modinput, say snow, the input is "snow"
    :param name: The name of the input stanza to create.
                 i.e. stanza [<input_type>://<name>] will be operated.
    :param operation: must be "disable" or "enable"
    """

    assert operation in ("disable", "enable")
    uri = _input_endpoint_ns(splunkd_uri, owner, app_name, input_type)
    uri += "/%s/%s" % (util.format_stanza_name(name), operation)
    msg = "Failed to %s data input in app=%s: %s://%s" % (
        operation, app_name, input_type, name)
    content_request(uri, session_key, "POST", None, msg)
