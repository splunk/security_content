"""
Copyright (C) 2005-2015 Splunk Inc. All Rights Reserved.
"""

import os
import os.path as op
import datetime
import sys
import gc
import urllib


def handle_tear_down_signals(callback):
    import signal

    signal.signal(signal.SIGTERM, callback)
    signal.signal(signal.SIGINT, callback)

    if os.name == "nt":
        signal.signal(signal.SIGBREAK, callback)


def datetime_to_seconds(dt):
    epoch_time = datetime.datetime.utcfromtimestamp(0)
    return (dt - epoch_time).total_seconds()


def is_true(val):
    value = str(val).strip().upper()
    if value in ("1", "TRUE", "T", "Y", "YES"):
        return True
    return False


def is_false(val):
    value = str(val).strip().upper()
    if value in ("0", "FALSE", "F", "N", "NO", "NONE", ""):
        return True
    return False


def remove_http_proxy_env_vars():
    for k in ("http_proxy", "https_proxy"):
        if k in os.environ:
            del os.environ[k]
        elif k.upper() in os.environ:
            del os.environ[k.upper()]


def get_appname_from_path(absolute_path):
    absolute_path = op.normpath(absolute_path)
    parts = absolute_path.split(os.path.sep)
    parts.reverse()
    for key in ("apps", "slave-apps", "master-apps"):
        try:
            idx = parts.index(key)
        except ValueError:
            continue
        else:
            try:
                if parts[idx + 1] == "etc":
                    return parts[idx - 1]
            except IndexError:
                pass
            continue
    #return None
    return "-"


def escape_cdata(data):
    # FIXME: This is a workaround for JIRA [addon-10459]
    data = data.decode("utf-8", errors="replace").encode("utf-8", errors="xmlcharrefreplace")
    data = data.replace("]]>", "]]&gt;")
    if data.endswith("]"):
        data = data[:-1] + "%5D"
    return data


def extract_datainput_name(stanza_name):
    """
    stansa_name: string like aws_s3://my_s3_data_input
    """

    sep = "://"
    try:
        idx = stanza_name.index(sep)
    except ValueError:
        return stanza_name

    return stanza_name[idx + len(sep):]


def escape_json_control_chars(json_str):
    control_chars = ((r"\n", "\\\\n"), (r"\r", "\\\\r"),
                     (r"\r\n", "\\\\r\\\\n"))
    for ch, replace in control_chars:
        json_str = json_str.replace(ch, replace)
    return json_str


def disable_stdout_buffer():
    os.environ["PYTHONUNBUFFERED"] = "1"
    sys.stdout = os.fdopen(sys.stdout.fileno(), "w", 0)
    gc.garbage.append(sys.stdout)


def format_stanza_name(name):
    return urllib.quote(name.encode("utf-8"), "")
