
import pytest
import logging
import os
import time
import pytest_check as check

from http import HTTPStatus
from modules.streams_service_api_helper import DSPApi
from modules.utils import read_spl, read_data
from modules.security_content_handler import prepare_test


# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)

@pytest.fixture
def header_token(token):
    return f"Bearer {token}"


@pytest.fixture
def api(env, tenant, header_token):
    return DSPApi(env, tenant, header_token)

@pytest.fixture
def test_file(test_file):
    prepare_test(test_file)
    return test_file


@pytest.fixture
def results_index(api):
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
    temp_index = api.create_temp_index("mc")
    yield temp_index
    # tear down the index
    api.delete_temp_index(temp_index["id"])


def test_ssa_ingestion_preview_example(api):
    ssa_detection_in_dsp_with_preview_session(api, 'troubleshoot.spl', "example.txt")


def test_ssa_ingestion_preview_windows(api):
    ssa_detection_in_dsp_with_preview_session(api, 'troubleshoot.spl', "example2.log")


def test_ssa_ingestion_index(api, results_index):
    ssa_detection_in_dsp(api, 'troubleshoot.spl', results_index, "example.txt")


def test_data_ingestion_preview(api):
    ssa_detection_in_dsp_with_preview_session(api, 'firehose.spl', "example.txt")


def test_data_ingestion_index(api, results_index):
    ssa_detection_in_dsp(api, 'firehose2.spl', results_index, "example.txt")


def test_ssa_example_detection_preview(api):
    ssa_detection_in_dsp_with_preview_session(api, 'detection.spl', "example.txt")


def test_ssa_example_detection_index(api, results_index):
    ssa_detection_in_dsp(api, 'detection2.spl', results_index, "example.txt")


## Helper Functions ##

def ssa_detection_in_dsp_with_preview_session(api, spl, source):

    spl = read_spl(api.env, spl)
    check.is_not_none(spl, "fail to read dummy spl file")

    preview_id = api.get_preview_id_from_spl(spl)
    check.is_not_none(preview_id, "failed to create a preview session %s" % spl)

    time.sleep(15)

    data = read_data(source)
    response_body = api.ingest_data(data)

    time.sleep(60)

    response, response_body = api.get_preview_data(preview_id)
    check.greater(response_body.get("currentNumberOfRecords"), 0, "Missing records in preview session.")

    response = api.stop_preview_session(preview_id)


def ssa_detection_in_dsp(api, spl, results_index, source):
    spl = read_spl(api.env, spl, results_index)
    check.is_not_none(spl, "fail to read dummy spl file")

    pipeline_id = api.create_pipeline_from_spl(spl)
    check.is_not_none(pipeline_id, "failed to create a pipeline")

    _pipeline_status = api.pipeline_status(pipeline_id)
    check.equal(_pipeline_status, "CREATED", f"Current status of pipeline {pipeline_id} should be CREATED")

    response_body = api.activate_pipeline(pipeline_id)
    check.equal(response_body.get("activated"), pipeline_id, f"pipeline {pipeline_id} should be successfully activate.")

    time.sleep(30)

    data = read_data(source)
    response_body = api.ingest_data(data)

    time.sleep(30)

    query = f"from index:{results_index['name']} | search source!=\"Search Catalog\""
    sid = api.submit_search_job(results_index['module'], query)
    check.is_not_none(sid, f"Failed to create a Search Job")

    time.sleep(30)

    response_body = api.get_search_job_results(sid)
    check.greater(len(response_body.get("results")), 0, "Search job didn't return any results")

    response, response_body = api.deactivate_pipeline(pipeline_id)
    check.equal(response.status_code, HTTPStatus.OK, f"The pipeline {pipeline_id} fails to deactivated.")

    response = api.delete_pipeline(pipeline_id)
    check.equal(response.status_code, HTTPStatus.NO_CONTENT, f"Fail to delete pipeline {pipeline_id}.")
