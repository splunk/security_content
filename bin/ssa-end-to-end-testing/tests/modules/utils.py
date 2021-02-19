import json
import logging
import os
import fileinput

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)

# Macros
PULSAR_SOURCE_CONNECTION_ID = f"29fb61f1-9342-48f5-9793-1afa008c377b"
PULSAR_SOURCE_TOPIC = f"persistent://ssa/egress/decorated-events-research2"
PULSAR_SINK_CONNECTION_ID = f"29fb61f1-9342-48f5-9793-1afa008c377b"
PULSAR_SINK_TOPIC = f"persistent://ssa/ingress/detection-events-research2"
READ_SSA_ENRICHED_EVENTS = f"| from read_ssa_enriched_events()"
READ_SSA_ENRICHED_EVENTS_EXPANDED = (
    f"| from pulsar(\"{PULSAR_SOURCE_CONNECTION_ID}\", \"{PULSAR_SOURCE_TOPIC}\")"
    f"| eval input_event=deserialize_json_object(value)"
    f"| select input_event"
    f"| eval _datamodels=ucast(map_get(input_event, \"_datamodels\"), \"collection<string>\", [])"
    f",body={{}}"
)
WRITE_SSA_DETECTED_EVENTS = f"| into write_ssa_detected_events();"

## dummy values ##
DETECTION_TYPE = f"anomaly"
DETECTION_ID = f"93fbec4e-0375-440c-8db3-4508eca470c4"
DETECTION_VERSION = f"1"
RISK_SEVERITY = f"low"
## dummy values ##

WRITE_SSA_DETECTED_EVENTS_EXPANDED = (
    f"| eval create_time=time()"
    f", type=\"{DETECTION_TYPE}\""
    f", detection_id=\"{DETECTION_ID}\""
    f", detection_version=\"{DETECTION_VERSION}\""
    f", risk_severity=\"{RISK_SEVERITY}\""
    f"| select create_time"
    f", start_time"
    f", end_time"
    f", type"
    f", detection_id"
    f", detection_version"
    f", risk_severity"
    f", entities"
    f", body"
    f"| eval id=concat(\"sha256:\", base64_encode(sha256(serialize_json())))"
    f"| select id, serialize_json() AS value"
    f"| into pulsar(\"{PULSAR_SINK_CONNECTION_ID}\", \"{PULSAR_SINK_TOPIC}\", id, value);"
)


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


def read_spl(file_name):
    file_path = os.path.join(os.path.dirname(__file__), 'spl', file_name)
    spl = open(file_path, "r").read()
    spl = replace_ssa_macros(spl)
    return spl

def replace_ssa_macros(spl):
    spl = spl.replace(READ_SSA_ENRICHED_EVENTS, READ_SSA_ENRICHED_EVENTS_EXPANDED)
    spl = spl.replace(WRITE_SSA_DETECTED_EVENTS, WRITE_SSA_DETECTED_EVENTS_EXPANDED)
    #spl = spl.replace("\n", " ")
    return spl

def read_data(file_name):
    file_path = os.path.join(os.path.dirname(__file__), 'data', file_name)
    data = "".join([line for line in fileinput.input(files=file_path)])
    return data
