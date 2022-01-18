import json
import logging
import os
import fileinput
import re
import io

from .data_manipulation import DataManipulation

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


# Macros
PULSAR_SOURCE_CONNECTION_ID_PLAYGROUND = f"29fb61f1-9342-48f5-9793-1afa008c377b"
PULSAR_SOURCE_TOPIC_PLAYGROUND = f"persistent://ssa/egress/decorated-events-research2"
PULSAR_SOURCE_CONNECTION_ID_STAGING = f"d156ed3a-1254-469a-bffc-9dd6eda97ac6"
PULSAR_SOURCE_TOPIC_STAGING = f"persistent://ssa/egress/decorated-events-research"

READ_SSA_ENRICHED_EVENTS_EXPANDED = (
    f"pulsar(\"__PULSAR_SOURCE_CONNECTION_ID__\", \"__PULSAR_SOURCE_TOPIC__\")"
    f"| eval input_event=deserialize_json_object(value)"
    f"| select input_event"
    f"| eval _datamodels=ucast(map_get(input_event, \"_datamodels\"), \"collection<string>\", [])"
    f",body={{}}"
)

# not used in the moment
# PULSAR_SINK_CONNECTION_ID = f"29fb61f1-9342-48f5-9793-1afa008c377b"
# PULSAR_SINK_TOPIC = f"persistent://ssa/ingress/detection-events-research2"

# ## dummy values ##
# DETECTION_TYPE = f"anomaly"
# DETECTION_ID = f"93fbec4e-0375-440c-8db3-4508eca470c4"
# DETECTION_VERSION = f"1"
# RISK_SEVERITY = f"low"
# ## dummy values ##

# WRITE_SSA_DETECTED_EVENTS_EXPANDED = (
#     f"| eval create_time=time()"
#     f", type=\"{DETECTION_TYPE}\""
#     f", detection_id=\"{DETECTION_ID}\""
#     f", detection_version=\"{DETECTION_VERSION}\""
#     f", risk_severity=\"{RISK_SEVERITY}\""
#     f"| select create_time"
#     f", start_time"
#     f", end_time"
#     f", type"
#     f", detection_id"
#     f", detection_version"
#     f", risk_severity"
#     f", entities"
#     f", body"
#     f"| eval id=concat(\"sha256:\", base64_encode(sha256(serialize_json())))"
#     f"| select id, serialize_json() AS value"
#     f"| into pulsar(\"{PULSAR_SINK_CONNECTION_ID}\", \"{PULSAR_SINK_TOPIC}\", id, value);"
# )


def fetch_token(file):
    with open(file) as f:
        data = json.load(f)
        try:
            token = data["data"]["token"]

        except RuntimeError as e:
            LOGGER.error(f"JSON is invalid, no IAC token found in Vault JSON output: {e}")
    return token


def request_headers(header_token):
    headers = {"Content-Type": "application/json", "Authorization": header_token}
    return headers


def check_source_sink(spl):
    match_sink = re.search(r"\|\s*into\s+write_ssa_detected_events\(\s*\)\s*;", spl)
    return match_sink


def manipulate_spl(env, spl, test_id):
    # Obtain the SSA source
    pulsar_source_connection_id, pulsar_source_topic = return_macros(env)
    source = READ_SSA_ENRICHED_EVENTS_EXPANDED\
        .replace("__PULSAR_SOURCE_CONNECTION_ID__", pulsar_source_connection_id)\
        .replace("__PULSAR_SOURCE_TOPIC__", pulsar_source_topic)
    # Obtain the test sink
    sink = f" eval test_id=\"{test_id}\" | into index(\"mc\", \"detection_testing\")"
    # Replace spl template with its `source` and `sink`
    spl = replace_ssa_macros(source, sink, spl)
    LOGGER.info(f"spl: {spl}")
    return spl


def read_spl(file_path, file_name):
    full_path = os.path.join(file_path, file_name)
    spl = open(full_path, "r").read()
    return spl


def replace_ssa_macros(source, sink, spl):
    spl = re.sub(r'read_ssa_enriched_events\(\s*\)', source, spl, flags=re.IGNORECASE)
    spl = re.sub(r'into write_ssa_detected_events()\(\s*\)', sink, spl, flags=re.IGNORECASE)
    return spl


def read_data(file_path, sourcetype):
    data = []
    if sourcetype == "WinEventLog:Security" or sourcetype == "WinEventLog":
        data_manipulation = DataManipulation()
        modified_file = data_manipulation.manipulate_timestamp(file_path, 'xmlwineventlog', 'WinEventLog:Security')
        date_rex = r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M'
        count = len(open(modified_file).readlines())

        i = 0
        file = fileinput.input(files=modified_file)
        event = file[0]
        start_position = 0

        for i in range(1, count):
            line = file[i]
            i = i + 1
            if re.match(date_rex, line):
                data.append(event)
                start_position = i
                event = line
            else:
                event = event + line


        data.append(event)
        fileinput.close()
    elif sourcetype == "xmlwineventlog":
        for line in fileinput.input(files=file_path):
            data.append(line)

    return data


def return_macros(env):
    if env == "playground":
        return PULSAR_SOURCE_CONNECTION_ID_PLAYGROUND, PULSAR_SOURCE_TOPIC_PLAYGROUND
    else:
        return PULSAR_SOURCE_CONNECTION_ID_STAGING, PULSAR_SOURCE_TOPIC_STAGING 