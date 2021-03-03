
import logging
import os
import time

from http import HTTPStatus
from modules.streams_service_api_helper import DSPApi
from modules.utils import read_spl, read_data
from modules.security_content_handler import prepare_test


# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)

# MACROS
SLEEP_TIME = 60
LOG_FILE = f"windows-security.log"


class SSADetectionTesting:

    def __init__(self, env, tenant, header_token):
        self.execution_passed = True
        self.env = env
        self.tenant = tenant
        self.header_token = f"Bearer {header_token}"
        self.api = DSPApi(env, tenant, self.header_token)
        self.test_results = {
            "test_result_msg": [],
            "overall_test_passed": True 
        }


    def test_dsp_pipeline(self):
        self.ssa_detection_in_dsp_with_preview_session('firehose.spl', LOG_FILE, "DSP Preview Session Test Minimal")
        self.ssa_detection_in_dsp('firehose.spl', LOG_FILE, "DSP Index Test Minimal")
        self.ssa_detection_in_dsp_with_preview_session('troubleshoot.spl', LOG_FILE, "SSA Preview Session Test Minimal")
        self.ssa_detection_in_dsp('troubleshoot.spl', LOG_FILE, "SSA Index Test Minimal")
        self.ssa_detection_in_dsp_with_preview_session('detection.spl', LOG_FILE, "SSA Preview Detection Testing Example")
        self.ssa_detection_in_dsp('detection.spl', LOG_FILE, "SSA Index Detection Testing Example")

        LOGGER.info('-----------------------------------')
        LOGGER.info('-------- test DSP Pipeline --------')
        LOGGER.info('-----------------------------------')
        for test_result in self.test_results["test_result_msg"]:
            LOGGER.info(test_result)
        LOGGER.info('-----------------------------------')

        return self.test_results["overall_test_passed"]


    def test_ssa_detections(self):
        self.test_results["overall_test_passed"] = True
        self.test_results["test_result_msg"] = []



        LOGGER.info('-----------------------------------')
        LOGGER.info('---------- test results -----------')
        LOGGER.info('-----------------------------------')
        for test_result in self.test_results["test_result_msg"]:
            LOGGER.info(test_result)
        LOGGER.info('-----------------------------------')


    ## Helper Functions ##

    def check_result(self, condition, error_message):
        try:
            assert condition
        except:
            self.execution_passed = False
            LOGGER.error(error_message)

    def write_test_results(self, test_name):
        if not self.execution_passed:
            msg = f"Detection test failed for {test_name}"
            LOGGER.error(msg)
            self.test_results["test_result_msg"].append(msg)
            self.test_results["overall_test_passed"] = False
        else:
            msg = f"Detection test successful for {test_name}"
            LOGGER.info(msg)
            self.test_results["test_result_msg"].append(msg)

    def ssa_detection_in_dsp_with_preview_session(self, spl, source, test_name):

        self.execution_passed = True

        spl = read_spl(self.api.env, spl)
        self.check_result(spl is not None, "fail to read dummy spl file")

        preview_id = self.api.get_preview_id_from_spl(spl)
        self.check_result(preview_id is not None, "failed to create a preview session %s" % spl)

        time.sleep(SLEEP_TIME)

        data = read_data(source)
        response_body = self.api.ingest_data(data)

        time.sleep(SLEEP_TIME)

        response, response_body = self.api.get_preview_data(preview_id)
        self.check_result(response_body.get("currentNumberOfRecords") > 0, "Missing records in preview session.")

        response = self.api.stop_preview_session(preview_id)

        self.write_test_results(test_name)


    def ssa_detection_in_dsp(self, spl, source, test_name):
        self.execution_passed = True

        self.results_index = self.api.create_temp_index("mc")

        time.sleep(SLEEP_TIME)

        spl = read_spl(self.api.env, spl, self.results_index)
        self.check_result(spl is not None, "fail to read dummy spl file")

        pipeline_id = self.api.create_pipeline_from_spl(spl)
        self.check_result(pipeline_id is not None, "failed to create a pipeline")

        _pipeline_status = self.api.pipeline_status(pipeline_id)
        self.check_result(_pipeline_status=="CREATED", f"Current status of pipeline {pipeline_id} should be CREATED")

        response_body = self.api.activate_pipeline(pipeline_id)
        self.check_result(response_body.get("activated")==pipeline_id, f"pipeline {pipeline_id} should be successfully activate.")

        time.sleep(SLEEP_TIME)

        data = read_data(source)
        response_body = self.api.ingest_data(data)

        time.sleep(SLEEP_TIME)

        query = f"from index:{self.results_index['name']}"
        sid = self.api.submit_search_job(self.results_index['module'], query)
        self.check_result(sid is not None, f"Failed to create a Search Job")

        time.sleep(SLEEP_TIME)

        response_body = self.api.get_search_job_results(sid)
        self.check_result(len(response_body.get("results")) > 0, "Search job didn't return any results")

        response, response_body = self.api.deactivate_pipeline(pipeline_id)
        self.check_result(response.status_code == HTTPStatus.OK, f"The pipeline {pipeline_id} fails to deactivated.")

        response = self.api.delete_pipeline(pipeline_id)
        self.check_result(response.status_code == HTTPStatus.NO_CONTENT, f"Fail to delete pipeline {pipeline_id}.")

        self.write_test_results(test_name)

        # Comment for testing
        #self.api.delete_temp_index(self.results_index["id"])