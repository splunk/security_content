import json
import logging
import os
import fileinput

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


# Macros
PULSAR_SOURCE_CONNECTION_ID_PLAYGROUND = f"29fb61f1-9342-48f5-9793-1afa008c377b"
PULSAR_SOURCE_TOPIC_PLAYGROUND = f"persistent://ssa/egress/decorated-events-research2"
PULSAR_SOURCE_CONNECTION_ID_STAGING = f"fd92bf9f-5d40-4c2e-bb75-bf0c3fc13980"
PULSAR_SOURCE_TOPIC_STAGING = f"persistent://ssa/egress/decorated-events-research"

READ_SSA_ENRICHED_EVENTS = f"| from read_ssa_enriched_events()"
READ_SSA_ENRICHED_EVENTS_EXPANDED = (
    f"| from pulsar(\"__PULSAR_SOURCE_CONNECTION_ID__\", \"__PULSAR_SOURCE_TOPIC__\")"
    f"| eval input_event=deserialize_json_object(value)"
    f"| select input_event"
    f"| eval _datamodels=ucast(map_get(input_event, \"_datamodels\"), \"collection<string>\", [])"
    f",body={{}}"
)

# not used in the moment
# PULSAR_SINK_CONNECTION_ID = f"29fb61f1-9342-48f5-9793-1afa008c377b"
# PULSAR_SINK_TOPIC = f"persistent://ssa/ingress/detection-events-research2"
WRITE_SSA_DETECTED_EVENTS = f"| into write_ssa_detected_events();"

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


def manipulate_spl(env, spl, results_index):
    spl = replace_ssa_macros(env, spl)
    if results_index is not None:
        # When an index is defined for a test, it writes the output of this pipeline to this index.
        # original_pipeline; => original_pipeline | into index("module", "index");
        module = results_index["module"]
        index = results_index["name"]
        spl = spl[:spl.rindex(";")] + f" | into index(\"{module}\", \"{index}\");"
    LOGGER.info(f"spl: {spl}")
    return spl


def read_spl(file_path, file_name):
    full_path = os.path.join(file_path, file_name)
    spl = open(full_path, "r").read()
    return spl


def replace_ssa_macros(env, spl):
    pulsar_source_connection_id, pulsar_source_topic = return_macros(env)
    macro_expanded = READ_SSA_ENRICHED_EVENTS_EXPANDED.replace("__PULSAR_SOURCE_CONNECTION_ID__", pulsar_source_connection_id)
    macro_expanded = macro_expanded.replace("__PULSAR_SOURCE_TOPIC__", pulsar_source_topic)
    spl = spl.replace(READ_SSA_ENRICHED_EVENTS, macro_expanded)
    spl = spl.replace(WRITE_SSA_DETECTED_EVENTS, ";")
    #spl = spl.replace("\n", " ")
    return spl


def read_data(file_name):
    file_path = os.path.join(os.path.dirname(__file__), 'data', file_name)
    data = "".join([line for line in fileinput.input(files=file_path)])
    return data


def return_macros(env):
    if env == "playground":
        return PULSAR_SOURCE_CONNECTION_ID_PLAYGROUND, PULSAR_SOURCE_TOPIC_PLAYGROUND
    else:
        return PULSAR_SOURCE_CONNECTION_ID_STAGING, PULSAR_SOURCE_TOPIC_STAGING 