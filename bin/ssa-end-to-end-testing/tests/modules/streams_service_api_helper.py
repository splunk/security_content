"""
helper functions to use the Streams Service API (v3beta1) to perform create, read and delete operations on
data pipeline.
API doc: https://dev.splunk.com/enterprise/reference/api/streams/v3beta1
"""

import logging
import os
import uuid
import requests

from http import HTTPStatus
#from constants import ML_MODEL_CONNECTOR_UUID
from modules.utils import request_headers


DSP_URL = f"https://api.playground.scp.splunk.com/research2/"
STREAMS_ENDPOINT = f"{DSP_URL}streams/v3beta1/"
SEARCH_EDNPOINT = f"{DSP_URL}search/v2beta1/"

# Streaming Pipelines REST endpoints
CONNECTIONS_ENDPOINT = f"{STREAMS_ENDPOINT}connections"
PIPELINES_ENDPOINT = f"{STREAMS_ENDPOINT}pipelines"
PIPELINES_COMPILE_ENDPOINT = f"{PIPELINES_ENDPOINT}/compile"
PIPELINES_VALIDATE_ENDPOINT = f"{PIPELINES_ENDPOINT}/validate"
PIPELINES_REGISTRY_ENDPOINT = f"{PIPELINES_ENDPOINT}/registry"
PREVIEW_SESSION_ENDPOINT = f"{STREAMS_ENDPOINT}preview-session"
PREVIEW_DATA_ENDPOINT = f"{STREAMS_ENDPOINT}preview-data"
INGEST_ENDPOINT = f"{DSP_URL}ingest/v1beta2/events"
SUBMIT_SEARCH_ENDPOINT = f"{SEARCH_EDNPOINT}jobs"

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


def compile_spl(header_token, spl):
    """
    Compile SPL text to a UPL JSON

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment
    spl:  str
        the SPL representation of a pipeline or function parameter to be compiled

    Returns
    -------
    upl:
        JSON representation of the compiled AST
    """
    data = {"spl": spl}
    LOGGER.debug(f"Compiling SPL into UPL")
    response = requests.post(PIPELINES_COMPILE_ENDPOINT, json=data, headers=request_headers(header_token))
    upl = response.json()
    LOGGER.info(f"POST compile response_body is: {upl}")
    LOGGER.info(f"Successfully compile spl to upl")
    return upl, response


def validate_upl(header_token, upl):
    """
    Validate whether the JSON representation of a pipeline is valid

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment
    upl: JSON
        JSON representation of the compiled AST of a pipeline

    Returns
    -------
    response_body: JSON
        returns whether or not the pipeline id valid. If valid, the response body returns 'success'
    """

    headers = {"Content-Type": "application/json", "Authorization": header_token}
    data = {"upl": upl}
    response = requests.post(PIPELINES_VALIDATE_ENDPOINT, json=data, headers=headers)
    response_body = response.json()
    LOGGER.info(f"POST pipelines/validate response_body is: {response_body}")
    if response.status_code == HTTPStatus.OK:
        LOGGER.info(f"UPL is validated.")
        return upl, response_body
    else:
        LOGGER.error(f"UPL validation failed: {response_body}")
        return response_body


def create_pipeline(header_token, upl):
    """
    POST pipelines endpoint to create a pipeline based on the valid upl

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment
    upl: JSON
        JSON representation of the validated pipeline details

    Returns
    -------
    pipline_id: UUID
        id of the created pipeline

    """

    headers = {"Content-Type": "application/json", "Authorization": header_token}
    set_test_id = uuid.uuid4().hex
    data = {
        "name": f"ssa_smoke_test_pipeline_helper_{set_test_id}",
        "description": "ssa_test_pipeline_description",
        "bypassValidation": "true",
        "data": upl
    }
    response = requests.post(PIPELINES_ENDPOINT, json=data, headers=headers)
    response_body = response.json()
    LOGGER.info(f"POST create pipeline response_body is: {response_body}")
    if response.status_code == HTTPStatus.CREATED:
        pipeline_id = response_body.get("id")
        LOGGER.info(f"Pipeline {pipeline_id} successfully created")
        return pipeline_id


def create_pipeline_from_spl(header_token, spl):
    """
    helper function to compile and validate from spl text, then create the pipeline

    """
    upl, _ = compile_spl(header_token, spl)
    validated_upl, _ = validate_upl(header_token, upl)
    pipeline_id = create_pipeline(header_token, validated_upl)
    LOGGER.info(f"pipeline id created is: {pipeline_id}")
    return pipeline_id


def activate_pipeline(header_token, pipeline_id):
    """
    POST pipelines/activate endpoint to activate an existing pipeline

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment
    pipeline_id: str
        pipeline UUID to activate

    Returns
    -------
    response_body: response JSON
        response body that contains pipeline status ACTIVATED
    """

    assert(pipeline_id is not None), "Must specify a 'pipeline_id'"

    headers = {"Content-Type": "application/json", "Authorization": header_token}
    pipelines_activate_endpoint = PIPELINES_ENDPOINT + "/" + pipeline_id + "/activate"

    data = {
        "activateLatestVersion": "true",
        "allowNonRestoredState": "true",
        "skipRestoreState": "true"
    }

    response = requests.post(pipelines_activate_endpoint, json=data, headers=headers)
    response_body = response.json()

    if response.status_code == HTTPStatus.OK:
        LOGGER.info(f"POST/pipelines/activate response_body is: {response_body}")
        pipeline_id = response_body.get("id")
        LOGGER.info(f"Pipeline {pipeline_id} successfully created")
        return response_body
    else:
        LOGGER.error(f"Failed to activate pipeline {pipeline_id}")
        return


def deactivate_pipeline(header_token, pipeline_id):
    """
    POST pipelines/deactivate endpoint to deactivate an existing pipeline

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment
    pipeline_id:
        pipeline UUID to deactivate

    Returns
    -------
    response_body: response JSON
        response body that contains the status of the pipeline after deactivation
    """

    assert(pipeline_id is not None), "Must specify a 'pipeline_id'"

    headers = {"Content-Type": "application/json", "Authorization": header_token}
    pipelines_deactivate_endpoint = PIPELINES_ENDPOINT + "/" + pipeline_id + "/deactivate"

    data = {
        "skipSavepoint": "true"
    }
    response = requests.post(pipelines_deactivate_endpoint, json=data, headers=headers)
    response_body = response.json()
    LOGGER.info(f"POST/pipelines/deactivate response_body is: {response_body}")
    return response, response_body


def delete_pipeline(header_token, pipeline_id):
    """
    Delete an existing pipeline using its pipeline UUID

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment
    pipeline_id:
        pipeline UUID of an existing pipeline

    Returns
    -------
    response status code
    """

    assert(pipeline_id is not None), "Must specify a 'pipeline_id'"

    headers = {"Content-Type": "application/json", "Authorization": header_token}
    delete_pipeline_endpoint = PIPELINES_ENDPOINT + "/" + pipeline_id
    response = requests.delete(delete_pipeline_endpoint, headers=headers)
    LOGGER.info(f"DELETE pipeline response status code is: {response.status_code}")
    return response


def pipeline_status(header_token, pipeline_id):
    """
    Returns the statues of an existing pipeline
    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment
    pipeline_id:
        pipeline UUID of an existing pipeline.

    Returns
    -------
    pipeline_status: str
        pipeline status can be CREATED, ACTIVATED, FINISHED, RESTARTING, FAILED.
    """
    assert(pipeline_id is not None), "Must specify a 'pipeline_id'"

    headers = {"Content-Type": "application/json", "Authorization": header_token}
    pipelines_status_endpoint = PIPELINES_ENDPOINT + "/" + pipeline_id

    response = requests.get(pipelines_status_endpoint, headers=headers)
    response_body = response.json()
    LOGGER.info(f"GET pipeline status response_body is: {response_body}")
    if response.status_code == HTTPStatus.OK:
        pipeline_status = response_body.get("status")
        return pipeline_status
    else:
        LOGGER.error(f"Fail to get current status of pipeline pipeline {pipeline_id}")
        return


def get_preview_id(header_token, upl):
    """
    POST preview-session endpoint to create a preview session for a pipeline

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment
    upl: JSON
        JSON representation of the pipeline details

    Returns
    -------
    preview_id: str
        preview session id
    """

    headers = {"Content-Type": "application/json", "Authorization": header_token}
    data = {
        "upl": upl
    }
    response = requests.post(PREVIEW_SESSION_ENDPOINT, json=data, headers=headers)
    response_body = response.json()
    LOGGER.info(f"POST preview session response_body is: {response_body}")
    # The preview sessions was started successfully
    if response.status_code == HTTPStatus.CREATED:
        preview_id = response_body.get("previewId")
        assert(preview_id is not None), "Must return a 'preview_id'"
        return preview_id


def get_preview_data(header_token, preview_id):
    """
    POST preview-data endpoint to get the preview data for a preview session

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment
    preview_id: str
        preview session id

    Returns
    -------
    response_body: response JSON
        the response would contain current number of records, preview data
    """

    assert(preview_id is not None), "Must specify a 'preview_id'"

    headers = {"Content-Type": "application/json", "Authorization": header_token}
    preview_data_endpoint = PREVIEW_DATA_ENDPOINT + "/" + str(preview_id)

    response = requests.get(preview_data_endpoint, headers=headers)
    response_body = response.json()
    LOGGER.info(f"GET preview data response_body is: {response_body}")

    if response.status_code != HTTPStatus.OK:
        LOGGER.error(f"Failed to preview data from the pipeline. Please check if the operator has been properly "
                     f"uploaded to DSP.")
        return
    else:
        return response, response_body


def stop_preview_session(header_token, preview_id):
    """
    Delete an existing pipeline using its pipeline UUID

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment
    preview_id: str
        preview session id

    Returns
    -------
    Boolean: True if preview session is stopped.
    """

    assert(preview_id is not None), "Must specify a 'preview_id'"
    headers = {"Content-Type": "application/json", "Authorization": header_token}
    stop_preview_session_endpoint = PREVIEW_SESSION_ENDPOINT + "/" + preview_id
    response = requests.delete(stop_preview_session_endpoint, headers=headers)
    LOGGER.info(f"DELETE/preview-session response status code is: {response.status_code}")
    return response


def get_preview_id_from_spl(header_token, spl):

    """
    helper function to compile and validate from spl text, then create the pipeline preview session

    """

    upl, _ = compile_spl(header_token, spl)
    validated_upl, _ = validate_upl(header_token, upl)
    preview_id = get_preview_id(header_token, validated_upl)
    LOGGER.info(f"preview id created is: {preview_id}")
    return preview_id


def get_connections(header_token):
    """
    Query the GET/connection endpoint, return a list of connection of a tenant.

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment

    Returns
    -------
    response_body
        Connection response body in JSON format
    """

    response = requests.get(CONNECTIONS_ENDPOINT, headers=request_headers(header_token))
    response_body = response.json()
    LOGGER.info(response.request.headers)
    LOGGER.info(f"GET connections response_body is: {response_body}")
    return response, response_body


def create_ml_model_connection(header_token):
    """
    Query the POST/connection endpoint to create a ML model connector for S3.

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment

    Returns
    -------
    response_body
        Connection response body in JSON format
    """
    set_test_id = uuid.uuid4().hex
    headers = {"Content-Type": "application/json", "Authorization": header_token}
    data = {
        "connectorId": ML_MODEL_CONNECTOR_UUID,
        "description": "Smoketest Connect to Amazon S3 to load machine learning models",
        "name": f"ML Model Connector for Amazon S3_{set_test_id}",
        "data": {
            "aws-access-key-id": AWS_ACCESS_KEY_ID,
            "aws-secret-access-key": AWS_SECRET_ACCESS_KEY
        }
    }
    response = requests.post(CONNECTIONS_ENDPOINT, json=data, headers=headers)
    response_body = response.json()
    LOGGER.info(f"POST connection response_body is: {response_body}")
    # The preview sessions was started successfully
    if response.status_code == HTTPStatus.CREATED:
        connector_id = response_body.get("id")
        return response_body, connector_id


def delete_connection(header_token, connection_id):
    """
   Delete an existing connection by its id.

   Parameters
   ----------
   header_token: str
       IAC token for DSP playground environment
   connection_id:
       UUID of an existing connection

   Returns
   -------
   response status code
   """

    assert(connection_id is not None), "Must specify a 'connection_id'"

    headers = {"Content-Type": "application/json", "Authorization": header_token}
    delete_connection_endpoint = CONNECTIONS_ENDPOINT + "/" + connection_id
    response = requests.delete(delete_connection_endpoint, headers=headers)
    LOGGER.info(f"DELETE connections response status code is: {response.status_code}")
    return response


def get_registry(header_token):
    """
    Query the GET/pipelines/registry endpoint, return a list of functions of a tenant.

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment

    Returns
    -------
    response_body
        Registry response body in JSON format
    """
    response = requests.get(PIPELINES_REGISTRY_ENDPOINT, headers=request_headers(header_token))
    try:
        assert response.status_code == HTTPStatus.OK, "Should return a list of functions"
    except AssertionError as error:
        LOGGER.error(error)
        raise error
    response_body = response.json()
    LOGGER.info(response.request.headers)
    #set registry reponse body to debug level as it will return too much log which is not always helpful
    LOGGER.debug(f"GET registry response_body is: {response_body}")
    return response_body


def ingest_data(header_token, data):
    """
    Send events

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment

    Returns
    -------
    response
        response body in JSON format
    """
    data = [{
        "body": data,
        "sourcetype": "WinEventLog"
        }]
    LOGGER.debug(f"Send Events")
    response = requests.post(INGEST_ENDPOINT, json=data, headers=request_headers(header_token))
    return response.json()


def submit_search_job(header_token, query):
    """
    Submit Search job

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment

    Returns
    -------
    sid
        sid to search job
    """
    data = {
        "query": query
    }
    LOGGER.debug(f"Submit Search Job")
    response = requests.post(SUBMIT_SEARCH_ENDPOINT, json=data, headers=request_headers(header_token))
    response_body = response.json()
    return response_body.get("sid")


def get_search_job_results(header_token, sid):
    """
    Get Searcj Job Results

    Parameters
    ----------
    header_token: str
        IAC token for DSP playground environment

    Returns
    -------
    response
        response body in JSON format
    """

    results_search_job_endpoint = SUBMIT_SEARCH_ENDPOINT + "/" + sid + "/results"
    response = requests.get(results_search_job_endpoint, headers=request_headers(header_token))
    response_body = response.json()
    return response_body
