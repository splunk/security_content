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


# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)

TENANT_PLAYGROUND = f"research2"
TENANT_STAGING = f"research"
BASE_URL_PLAYGROUND = f"https://api.playground.scp.splunk.com/"
BASE_URL_STAGING = f"https://api.staging.scp.splunk.com/"

# Streaming Pipelines REST endpoints
CONNECTIONS_ENDPOINT = f"streams/v3beta1/connections"
PIPELINES_ENDPOINT = f"streams/v3beta1/pipelines"
PIPELINES_COMPILE_ENDPOINT = f"streams/v3beta1/pipelines/compile"
PIPELINES_VALIDATE_ENDPOINT = f"streams/v3beta1/pipelines/validate"
PIPELINES_REGISTRY_ENDPOINT = f"streams/v3beta1/pipelines/registry"
PREVIEW_SESSION_ENDPOINT = f"streams/v3beta1/preview-session"
PREVIEW_DATA_ENDPOINT = f"streams/v3beta1/preview-data"
INGEST_ENDPOINT = f"ingest/v1beta2/events"
SUBMIT_SEARCH_ENDPOINT = f"search/v2beta1/jobs"
DATASETS_ENDPOINT = f"catalog/v2beta1/datasets"


class DSPApi:

    def __init__(self, env, tenant, header_token):
        self.env = env
        self.tenant = tenant
        self.header_token = header_token


    def return_api_endpoint(self, endpoint):
        if self.env == 'playground':
            return f"{BASE_URL_PLAYGROUND}{TENANT_PLAYGROUND}/{endpoint}"
        else:
            return f"{BASE_URL_STAGING}{TENANT_STAGING}/{endpoint}"


    def compile_spl(self, spl):
        """
        Compile SPL text to a UPL JSON

        Parameters
        ----------
        spl:  str
            the SPL representation of a pipeline or function parameter to be compiled

        Returns
        -------
        upl:
            JSON representation of the compiled AST
        """
        data = {"spl": spl}
        LOGGER.debug(f"Compiling SPL into UPL")
        response = requests.post(self.return_api_endpoint(PIPELINES_COMPILE_ENDPOINT), json=data, headers=request_headers(self.header_token))
        upl = response.json()
        LOGGER.info(f"POST compile response_body is: {upl}")
        LOGGER.info(f"Successfully compile spl to upl")
        return upl, response


    def validate_upl(self, upl):
        """
        Validate whether the JSON representation of a pipeline is valid

        Parameters
        ----------
        upl: JSON
            JSON representation of the compiled AST of a pipeline

        Returns
        -------
        response_body: JSON
            returns whether or not the pipeline id valid. If valid, the response body returns 'success'
        """

        headers = {"Content-Type": "application/json", "Authorization": self.header_token}
        data = {"upl": upl}
        response = requests.post(self.return_api_endpoint(PIPELINES_VALIDATE_ENDPOINT), json=data, headers=headers)
        response_body = response.json()
        LOGGER.info(f"POST pipelines/validate response_body is: {response_body}")
        if response.status_code == HTTPStatus.OK:
            LOGGER.info(f"UPL is validated.")
            return upl, response_body
        else:
            LOGGER.error(f"UPL validation failed: {response_body}")
            return response_body


    def create_pipeline(self, upl):
        """
        POST pipelines endpoint to create a pipeline based on the valid upl

        Parameters
        ----------
        upl: JSON
            JSON representation of the validated pipeline details

        Returns
        -------
        pipline_id: UUID
            id of the created pipeline

        """

        headers = {"Content-Type": "application/json", "Authorization": self.header_token}
        set_test_id = uuid.uuid4().hex
        data = {
            "name": f"ssa_smoke_test_pipeline_helper_{set_test_id}",
            "description": "ssa_test_pipeline_description",
            "bypassValidation": "true",
            "data": upl
        }
        response = requests.post(self.return_api_endpoint(PIPELINES_ENDPOINT), json=data, headers=headers)
        response_body = response.json()
        LOGGER.info(f"POST create pipeline response_body is: {response_body}")
        if response.status_code == HTTPStatus.CREATED:
            pipeline_id = response_body.get("id")
            LOGGER.info(f"Pipeline {pipeline_id} successfully created")
            return pipeline_id


    def create_pipeline_from_spl(self, spl):
        """
        helper function to compile and validate from spl text, then create the pipeline

        """
        upl, _ = self.compile_spl(spl)
        validated_upl, _ = self.validate_upl(upl)
        pipeline_id = self.create_pipeline(validated_upl)
        LOGGER.info(f"pipeline id created is: {pipeline_id}")
        return pipeline_id


    def activate_pipeline(self, pipeline_id):
        """
        POST pipelines/activate endpoint to activate an existing pipeline

        Parameters
        ----------
        pipeline_id: str
            pipeline UUID to activate

        Returns
        -------
        response_body: response JSON
            response body that contains pipeline status ACTIVATED
        """

        assert(pipeline_id is not None), "Must specify a 'pipeline_id'"

        headers = {"Content-Type": "application/json", "Authorization": self.header_token}
        pipelines_activate_endpoint = self.return_api_endpoint(PIPELINES_ENDPOINT) + "/" + pipeline_id + "/activate"

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


    def deactivate_pipeline(self, pipeline_id):
        """
        POST pipelines/deactivate endpoint to deactivate an existing pipeline

        Parameters
        ----------
        pipeline_id:
            pipeline UUID to deactivate

        Returns
        -------
        response_body: response JSON
            response body that contains the status of the pipeline after deactivation
        """

        assert(pipeline_id is not None), "Must specify a 'pipeline_id'"

        headers = {"Content-Type": "application/json", "Authorization": self.header_token}
        pipelines_deactivate_endpoint = self.return_api_endpoint(PIPELINES_ENDPOINT) + "/" + pipeline_id + "/deactivate"

        data = {
            "skipSavepoint": "true"
        }
        response = requests.post(pipelines_deactivate_endpoint, json=data, headers=headers)
        response_body = response.json()
        LOGGER.info(f"POST/pipelines/deactivate response_body is: {response_body}")
        return response, response_body


    def delete_pipeline(self, pipeline_id):
        """
        Delete an existing pipeline using its pipeline UUID

        Parameters
        ----------
        pipeline_id:
            pipeline UUID of an existing pipeline

        Returns
        -------
        response status code
        """

        assert(pipeline_id is not None), "Must specify a 'pipeline_id'"

        headers = {"Content-Type": "application/json", "Authorization": self.header_token}
        delete_pipeline_endpoint = self.return_api_endpoint(PIPELINES_ENDPOINT) + "/" + pipeline_id
        response = requests.delete(delete_pipeline_endpoint, headers=headers)
        LOGGER.info(f"DELETE pipeline response status code is: {response.status_code}")
        return response


    def pipeline_status(self, pipeline_id):
        """
        Returns the statues of an existing pipeline
        Parameters
        ----------
        pipeline_id:
            pipeline UUID of an existing pipeline.

        Returns
        -------
        pipeline_status: str
            pipeline status can be CREATED, ACTIVATED, FINISHED, RESTARTING, FAILED.
        """
        assert(pipeline_id is not None), "Must specify a 'pipeline_id'"

        headers = {"Content-Type": "application/json", "Authorization": self.header_token}
        pipelines_status_endpoint = self.return_api_endpoint(PIPELINES_ENDPOINT) + "/" + pipeline_id

        response = requests.get(pipelines_status_endpoint, headers=headers)
        response_body = response.json()
        LOGGER.info(f"GET pipeline status response_body is: {response_body}")
        if response.status_code == HTTPStatus.OK:
            pipeline_status = response_body.get("status")
            return pipeline_status
        else:
            LOGGER.error(f"Fail to get current status of pipeline pipeline {pipeline_id}")
            return


    def get_preview_id(self, upl):
        """
        POST preview-session endpoint to create a preview session for a pipeline

        Parameters
        ----------
        upl: JSON
            JSON representation of the pipeline details

        Returns
        -------
        preview_id: str
            preview session id
        """

        headers = {"Content-Type": "application/json", "Authorization": self.header_token}
        data = {
            "upl": upl
        }
        response = requests.post(self.return_api_endpoint(PREVIEW_SESSION_ENDPOINT), json=data, headers=headers)
        response_body = response.json()
        LOGGER.info(f"POST preview session response_body is: {response_body}")
        # The preview sessions was started successfully
        if response.status_code == HTTPStatus.CREATED:
            preview_id = response_body.get("previewId")
            assert(preview_id is not None), "Must return a 'preview_id'"
            return preview_id


    def get_preview_data(self, preview_id):
        """
        POST preview-data endpoint to get the preview data for a preview session

        Parameters
        ----------
        preview_id: str
            preview session id

        Returns
        -------
        response_body: response JSON
            the response would contain current number of records, preview data
        """

        assert(preview_id is not None), "Must specify a 'preview_id'"

        headers = {"Content-Type": "application/json", "Authorization": self.header_token}
        preview_data_endpoint = self.return_api_endpoint(PREVIEW_DATA_ENDPOINT) + "/" + str(preview_id)

        response = requests.get(preview_data_endpoint, headers=headers)
        response_body = response.json()
        LOGGER.info(f"GET preview data response_body is: {response_body}")

        if response.status_code != HTTPStatus.OK:
            LOGGER.error(f"Failed to preview data from the pipeline. Please check if the operator has been properly "
                         f"uploaded to DSP.")
            return
        else:
            return response, response_body


    def stop_preview_session(self, preview_id):
        """
        Delete an existing pipeline using its pipeline UUID

        Parameters
        ----------
        preview_id: str
            preview session id

        Returns
        -------
        Boolean: True if preview session is stopped.
        """

        assert(preview_id is not None), "Must specify a 'preview_id'"
        headers = {"Content-Type": "application/json", "Authorization": self.header_token}
        stop_preview_session_endpoint = self.return_api_endpoint(PREVIEW_SESSION_ENDPOINT) + "/" + str(preview_id)
        response = requests.delete(stop_preview_session_endpoint, headers=headers)
        LOGGER.info(f"DELETE/preview-session response status code is: {response.status_code}")
        return response


    def get_preview_id_from_spl(self, spl):

        """
        helper function to compile and validate from spl text, then create the pipeline preview session

        """

        upl, _ = self.compile_spl(spl)
        validated_upl, _ = self.validate_upl(upl)
        preview_id = self.get_preview_id(validated_upl)
        LOGGER.info(f"preview id created is: {preview_id}")
        return preview_id


    def ingest_data(self, data):
        """
        Send events

        Parameters
        ----------
        data: str
            datafile

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
        response = requests.post(self.return_api_endpoint(INGEST_ENDPOINT), json=data, headers=request_headers(self.header_token))
        return response.json()


    def submit_search_job(self, module, query):
        """
        Submit Search job

        Parameters
        ----------
        module: str
            module where this query will be run on (default: `mc`)
        query: str
            SPL of the search query

        Returns
        -------
        sid
            sid to search job
        """
        data = {
            "query": query,
            "module": module
        }
        LOGGER.debug(f"Submit Search Job")
        response = requests.post(self.return_api_endpoint(SUBMIT_SEARCH_ENDPOINT), json=data, headers=request_headers(self.header_token))
        response_body = response.json()
        return response_body.get("sid")


    def get_search_job_results(self, sid):
        """
        Get Search Job Results

        Parameters
        ----------
        sid: str
            ID of the search. Returned value from `submit_search_job`

        Returns
        -------
        response
            response body in JSON format
        """

        results_search_job_endpoint = self.return_api_endpoint(SUBMIT_SEARCH_ENDPOINT) + "/" + sid + "/results"
        response = requests.get(results_search_job_endpoint, headers=request_headers(self.header_token))
        response_body = response.json()
        return response_body


    def create_temp_index(self, module):
        """
        Creates an index under module

        Parameters
        @param module: str
            module under this index will be created
        @return:
            index object dictionary
        """
        index_name = f"temp_st_{uuid.uuid1()}".replace("-", "_")
        data = {
            "module": module,
            "name": index_name,
            "kind": "index",
            "disabled": False
        }
        response = requests.post(self.return_api_endpoint(DATASETS_ENDPOINT), headers=request_headers(self.header_token), json=data)
        return response.json()


    def delete_temp_index(self, index_id):
        """
        Deletes an index

        @param index_id:
            Index ID
        @return:
            response status code from API
        """
        datasets_endpoint_api = self.return_api_endpoint(DATASETS_ENDPOINT)
        delete_url = f"{datasets_endpoint_api}/{index_id}"
        response = requests.delete(delete_url, headers=request_headers(self.header_token))
        return response.status_code

