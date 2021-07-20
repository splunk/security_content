import logging
import os
import time
import sys

from http import HTTPStatus
from modules.streams_service_api_helper import DSPApi
from modules.utils import check_source_sink, manipulate_spl, read_spl, read_data
from ssa_test import assert_results

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)

# MACROS
SLEEP_TIME_CREATE_INDEX = 10
SLEEP_TIME_ACTIVATE_PIPELINE = 10
SLEEP_TIME_SEND_DATA = 30
WAIT_CYCLE = 20
MAX_EXECUTION_TIME_LIMIT = 300  # per detection test

TEST_DATASET = 'windows-security_small.txt'


class SSADetectionTesting:

    def __init__(self, env, tenant, header_token):
        self.execution_passed = True
        self.max_execution_time = MAX_EXECUTION_TIME_LIMIT
        self.env = env
        self.tenant = tenant
        self.header_token = f"Bearer {header_token}"
        self.api = DSPApi(env, tenant, self.header_token)
        self.test_results = {}

    def test_dsp_pipeline(self):

        file_path_data = os.path.join(os.path.dirname(__file__), 'data', TEST_DATASET)
        file_path_spl = os.path.join(os.path.dirname(__file__), 'spl')

        test_spls = ['troubleshoot.spl', 'detection.spl']
        test_names = [
            "SSA Index Test Minimal",
            "SSA Index Detection Testing Example"
        ]

        test_results = []
        for i in range(0, len(test_spls)):
            self.max_execution_time = MAX_EXECUTION_TIME_LIMIT
            test_result = self.ssa_detection_test(read_spl(file_path_spl, test_spls[i]), file_path_data, test_names[i])
            test_results.append(test_result.copy())

        passed = True

        LOGGER.info('-----------------------------------')
        LOGGER.info('-------- test DSP Pipeline --------')
        LOGGER.info('-----------------------------------')
        for test_result in test_results:
            LOGGER.info(test_result['msg'])
            passed = passed and test_result['result']
        LOGGER.info('-----------------------------------')

        return passed

    def test_ssa_detections(self, test_obj):
        LOGGER.info('Test SSA Detection: ' + test_obj["detection_obj"]["name"])
        self.max_execution_time = MAX_EXECUTION_TIME_LIMIT
        file_path_attack_data = test_obj["attack_data_file_path"]

        test_results = self.ssa_detection_test(test_obj["detection_obj"]["search"], file_path_attack_data,
                                               "SSA Smoke Test " + test_obj["test_obj"]["name"],
                                               test_obj['test_obj']['tests'][0]['pass_condition'])

        return test_results

    ## Helper Functions ##

    def update_execution_time(self, time_frame):
        self.max_execution_time = self.max_execution_time - WAIT_CYCLE
        if self.max_execution_time < 0:
            return True
        else:
            return False

    def wait_time(self, time_in_s):
        time.sleep(time_in_s)
        return self.update_execution_time(time_in_s)

    def ssa_detection_test_init(self):
        self.cleanup_old_pipelines()
        self.test_results["result"] = True
        self.test_results["msg"] = ""
        self.results_index = self.api.create_temp_index("mc")
        self.created_pipelines = []
        self.activated_pipelines = []

    def cleanup_old_pipelines(self):
        pipelines = self.api.get_pipelines()
        yesterday = (time.time() - 24*3600) * 1000  # milliseconds
        for pipeline in pipelines:
            if pipeline['name'].startswith("ssa_smoke_test_pipeline_helper") and pipeline['createDate'] < yesterday:
                if pipeline['status'] == 'ACTIVATED':
                    # deactivate pipeline
                    resp, _ = self.api.deactivate_pipeline(pipeline['id'])
                    if resp.status_code != HTTPStatus.OK:
                        LOGGER.error("Error deactivating old pipeline %s: %s", pipeline['name'], resp.text)

                # delete pipeline
                resp = self.api.delete_pipeline(pipeline['id'])
                if resp.status_code != HTTPStatus.NO_CONTENT:
                    LOGGER.error("Error deleting old pipeline %s: %s", pipeline['name'], resp.text)
                else:
                    LOGGER.warning("Found and deleted an old pipeline: %s", pipeline['name'])

    def ssa_detection_test_main(self, spl, source, test_name, pass_condition):
        self.execution_passed = True

        self.wait_time(SLEEP_TIME_CREATE_INDEX)

        check_ssa_spl = check_source_sink(spl)
        spl = manipulate_spl(self.api.env, spl, self.results_index)
        assert spl is not None, "fail to manipulate spl file"

        pipeline_id = self.api.create_pipeline_from_spl(spl)
        assert pipeline_id is not None, "failed to create a pipeline"

        _pipeline_status = self.api.pipeline_status(pipeline_id)
        assert _pipeline_status == "CREATED", f"Current status of pipeline {pipeline_id} should be CREATED"
        self.created_pipelines.append(pipeline_id)

        response_body = self.api.activate_pipeline(pipeline_id)
        assert response_body.get("activated") == pipeline_id, f"pipeline {pipeline_id} should be successfully activate."
        self.activated_pipelines.append(pipeline_id)

        self.wait_time(SLEEP_TIME_ACTIVATE_PIPELINE)

        if not check_ssa_spl:
            msg = f"Detection test successful for {test_name}"
            LOGGER.warning(f"Test not completed. Detection seems deprecated, and will not send messages to SSA")
            self.test_results["msg"] = msg
            return self.test_results

        data = read_data(source)
        LOGGER.info("Sending (%d) events" % (len(data)))

        assert len(data) > 0, "No events to send, skip to next test."

        for d in data:
            response_body = self.api.ingest_data(d)

        self.wait_time(SLEEP_TIME_SEND_DATA)

        search_results = False
        max_execution_time_reached = False

        while not (search_results or max_execution_time_reached):
            max_execution_time_reached = self.wait_time(WAIT_CYCLE)
            query = f"from indexes('{self.results_index['name']}') | search source!=\"Search Catalog\" "
            sid = self.api.submit_search_job(self.results_index['module'], query)
            assert sid is not None, f"Failed to create a Search Job"

            job_finished = False
            while not job_finished:
                self.wait_time(WAIT_CYCLE)
                result = self.api.check_search_job_finished(sid)
                job_finished = result

            results = self.api.get_search_job_results(sid)
            search_results = (len(results) > 0)
            if not search_results:
                LOGGER.info(
                    f"Search didn't return any results. Retrying in {WAIT_CYCLE}s, max execution time left {self.max_execution_time}s")

        if not results:
            LOGGER.warning("Search job didn't return any results")

        LOGGER.info('Received %s result(s)', len(results))
        test_passed = assert_results(pass_condition, results)
        assert test_passed, f"Pass condition {pass_condition} not satisfied"

        msg = f"Detection test successful for {test_name}"
        LOGGER.info(msg)
        self.test_results["msg"] = msg

        return self.test_results

    def ssa_detection_test_teardown(self):
        """
        Deactivate and deletes pipelines, deletes results indexes,
        and when it fails it shows pipelines and result indexes that were not removed.
        :return:
        None
        """
        deactivate_pipeline = lambda p: self.api.deactivate_pipeline(p)[0].status_code == HTTPStatus.OK
        delete_pipeline = lambda p: self.api.delete_pipeline(p).status_code == HTTPStatus.NO_CONTENT
        delete_index = lambda p: self.api.delete_temp_index(p["id"]) == HTTPStatus.NO_CONTENT
        self.activated_pipelines = [p for p in self.activated_pipelines if not deactivate_pipeline(p)]
        self.created_pipelines = [p for p in self.created_pipelines if not delete_pipeline(p)]
        if len(self.activated_pipelines) > 0 or len(self.created_pipelines) > 0 or not delete_index(self.results_index):
            LOGGER.warning("Not all SCS resources fred up")
            LOGGER.info(f"Created Pipelines: {','.join(self.created_pipelines)}")
            LOGGER.info(f"Active Pipelines: {','.join(self.activated_pipelines)}")
            LOGGER.info(f"Result Indexes: {self.results_index}")
        else:
            LOGGER.info("Testing successfully cleaned up")

    def ssa_detection_test(self, spl, source, test_name, pass_condition='@count_gt(0)'):
        self.ssa_detection_test_init()
        try:
            test_result = self.ssa_detection_test_main(spl, source, test_name, pass_condition)
            self.ssa_detection_test_teardown()
            return test_result
        except AssertionError as e:
            self.ssa_detection_test_teardown()
            LOGGER.error(e.args[0])
            LOGGER.error(f"Detection test failure for {test_name}")
            return {"result": False,
                    "msg": f"Detection test failure for {test_name}"}
        except Exception as e:
            self.ssa_detection_test_teardown()
            LOGGER.exception(f"Detection test failure for {test_name} (perhaps SCS problems)")
            return {"result": False,
                    "msg": f"Detection test failure for {test_name} (perhaps SCS problems)"}

    # only for troubleshooting
    # def ssa_detection_in_dsp_with_preview_session(self, spl, source, test_name):

    #     self.execution_passed = True

    #     spl = manipulate_spl(self.api.env, spl)
    #     self.check_result(spl is not None, "fail to read dummy spl file")

    #     preview_id = self.api.get_preview_id_from_spl(spl)
    #     self.check_result(preview_id is not None, "failed to create a preview session %s" % spl)

    #     time.sleep(SLEEP_TIME_SHORT)

    #     data = read_data(source)
    #     response_body = self.api.ingest_data(data)

    #     time.sleep(SLEEP_TIME_LONG)

    #     response, response_body = self.api.get_preview_data(preview_id)
    #     self.check_result(response_body.get("currentNumberOfRecords") > 0, "Missing records in preview session.")

    #     response = self.api.stop_preview_session(preview_id)

    #     self.write_test_results(test_name)
