
import pytest
import logging
import os
import time

from http import HTTPStatus
from modules.streams_service_api_helper import compile_spl, create_pipeline_from_spl, pipeline_status, activate_pipeline, ingest_data, get_preview_id_from_spl, get_preview_data, submit_search_job, get_search_job_results, stop_preview_session, deactivate_pipeline, delete_pipeline, create_temp_index, delete_temp_index
from modules.utils import read_spl, read_data
import pytest_check as check

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


@pytest.fixture
def results_index(token):
    """
    Fixture that creates an temporary index, and tears it down.

    @todo
        Implement a safe tear down version of this. When an exception happens in the test, we can't guarantee
        that we won't have orphan indexes.
    @param token:
        This parameter is passed by `pytest`
    @return:
        Returns a descriptor of the index as a dictionary
    """
    header_token = f"Bearer {token}"
    temp_index = create_temp_index(header_token, module="mc")
    yield temp_index
    # tear down the index
    delete_temp_index(header_token, temp_index["id"])


def test_data_ingestion_preview(token):
    assert (token is not None), "scloud token is missing"
    header_token = f"Bearer {token}"

    ssa_detection_in_dsp_with_preview_session(header_token, 'firehose.spl')


def test_data_ingestion_index(token, results_index):
    assert (token is not None), "scloud token is missing"
    header_token = f"Bearer {token}"

    ssa_detection_in_dsp(header_token, 'firehose2.spl', results_index)


def test_ssa_example_detection_preview(token):
    assert (token is not None), "scloud token is missing"
    header_token = f"Bearer {token}"

    ssa_detection_in_dsp_with_preview_session(header_token, 'detection.spl')


def test_ssa_example_detection(token, results_index):
    assert (token is not None), "scloud token is missing"
    header_token = f"Bearer {token}"

    ssa_detection_in_dsp(header_token, 'detection2.spl', results_index)


## Helper Functions ##

def ssa_detection_in_dsp_with_preview_session(header_token, spl):

    spl = read_spl(spl)
    assert (spl is not None), "fail to read dummy spl file"

    preview_id = get_preview_id_from_spl(header_token, spl)
    assert preview_id is not None

    time.sleep(30)

    data = read_data(f"example.txt")
    response_body = ingest_data(header_token, data)

    response, response_body = get_preview_data(header_token, preview_id)
    check.greater(response_body.get("currentNumberOfRecords"), 0, "Missing records in preview session.")

    response = stop_preview_session(header_token, preview_id)


def ssa_detection_in_dsp(header_token, spl, results_index):
    spl = read_spl(spl, results_index)
    assert (spl is not None), "fail to read dummy spl file"

    pipeline_id = create_pipeline_from_spl(header_token, spl)
    assert pipeline_id is not None

    _pipeline_status = pipeline_status(header_token, pipeline_id)
    assert _pipeline_status == "CREATED", f"Current status of pipeline {pipeline_id} should be CREATED"

    response_body = activate_pipeline(header_token, pipeline_id)
    assert response_body.get("activated") == pipeline_id, f"pipeline {pipeline_id} should be successfully activate."

    time.sleep(30)

    data = read_data(f"example.txt")
    response_body = ingest_data(header_token, data)

    time.sleep(30)

    sid = submit_search_job(header_token, results_index['module'], f"from index:{results_index['name']} | search source!=\"Search Catalog\"")
    assert sid is not None

    time.sleep(30)

    response_body = get_search_job_results(header_token, sid)
    check.greater(len(response_body.get("results")), 0, "Search job didn't return any results")

    response, response_body = deactivate_pipeline(header_token, pipeline_id)
    assert response.status_code == HTTPStatus.OK,  f"The pipeline {pipeline_id} fails to deactivated."

    response = delete_pipeline(header_token, pipeline_id)
    assert response.status_code == HTTPStatus.NO_CONTENT, f"Fail to delete pipeline {pipeline_id}."
