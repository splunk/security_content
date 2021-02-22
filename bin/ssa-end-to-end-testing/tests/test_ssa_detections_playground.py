
import pytest
import logging
import os
import time

from http import HTTPStatus
from modules.streams_service_api_helper import compile_spl, create_pipeline_from_spl, pipeline_status, activate_pipeline, ingest_data, get_preview_id_from_spl, get_preview_data, submit_search_job, get_search_job_results, stop_preview_session, deactivate_pipeline, delete_pipeline
from modules.utils import read_spl, read_data
import pytest_check as check

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


def test_data_ingestion_preview(token):
    assert (token is not None), "scloud token is missing"
    header_token = f"Bearer {token}"

    ssa_detection_in_dsp_with_preview_session(header_token, 'firehose.spl')


def test_data_ingestion(token):
    assert (token is not None), "scloud token is missing"
    header_token = f"Bearer {token}"

    ssa_detection_in_dsp(header_token, 'firehose2.spl')


def test_ssa_example_detection_preview(token):
    assert (token is not None), "scloud token is missing"
    header_token = f"Bearer {token}"

    ssa_detection_in_dsp_with_preview_session(header_token, 'detection.spl')


def test_ssa_example_detection(token):
    assert (token is not None), "scloud token is missing"
    header_token = f"Bearer {token}"

    ssa_detection_in_dsp(header_token, 'detection2.spl')


## Helper Functions ##

def ssa_detection_in_dsp_with_preview_session(header_token, spl):

    spl = read_spl(spl)
    assert (spl is not None), "fail to read dummy spl file"

    preview_id = get_preview_id_from_spl(header_token, spl)
    assert preview_id is not None

    data = read_data(f"example.txt")
    response_body = ingest_data(header_token, data)

    response, response_body = get_preview_data(header_token, preview_id)
    check.greater(response_body.get("currentNumberOfRecords"), 0, "Missing records in preview session.")

    response = stop_preview_session(header_token, preview_id)


def ssa_detection_in_dsp(header_token, spl):
    spl = read_spl(spl)
    assert (spl is not None), "fail to read dummy spl file"

    pipeline_id = create_pipeline_from_spl(header_token, spl)
    assert pipeline_id is not None

    _pipeline_status = pipeline_status(header_token, pipeline_id)
    assert _pipeline_status == "CREATED", f"Current status of pipeline {pipeline_id} should be CREATED"

    response_body = activate_pipeline(header_token, pipeline_id)
    assert response_body.get("activated") == pipeline_id, f"pipeline {pipeline_id} should be successfully activate."

    data = read_data(f"example.txt")
    response_body = ingest_data(header_token, data)

    sid = submit_search_job(header_token, "from index:main")
    assert sid is not None

    response_body = get_search_job_results(header_token, sid)
    check.greater(len(response_body.get("results")), 0, "Search job didn't return any results")

    response, response_body = deactivate_pipeline(header_token, pipeline_id)
    assert response.status_code == HTTPStatus.OK,  f"The pipeline {pipeline_id} fails to deactivated."

    response = delete_pipeline(header_token, pipeline_id)
    assert response.status_code == HTTPStatus.NO_CONTENT, f"Fail to delete pipeline {pipeline_id}."
