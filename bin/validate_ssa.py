import yaml
import re
import os
import subprocess
import urllib.request
import tempfile
import argparse
import sys
import coloredlogs
import logging

SSML_CWD = ".humvee"
HUMVEE_URL = "https://repo.splunk.com/artifactory/maven-splunk-local/com/splunk/humvee-scala_2.11/1.2.1-SNAPSHOT/humvee-scala_2.11-1.2.1-20201022.220521-1.jar"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(coloredlogs.ColoredFormatter("%(asctime)s - %(levelname)s - %(message)s%(detail)s"))
logger.addHandler(handler)


def log(level, msg, detail=None):
    args = {'detail': ""} if detail is None else {'detail': "\n%s" % detail}
    logger.log(level, msg, extra=args)


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--skip-errors', action='store_true', default=False)
    parser.add_argument('--debug', action='store_true', default=False)
    parser.add_argument('test_files', type=str, nargs='+', help="test files to be checked")
    parsed = parser.parse_args(args)
    if parsed.debug:
        logger.setLevel(logging.DEBUG)
    build_humvee()
    status = True
    passed_tests = []
    failed_tests = []
    for t in parsed.test_files:
        cur_status = test_detection(t, parsed)
        status = status & cur_status
        if cur_status:
            passed_tests.append(t)
        else:
            failed_tests.append(t)
        if not status and not parsed.skip_errors:
            _exit(1, passed_tests, failed_tests)
    if status:
        _exit(0, passed_tests, failed_tests)
    else:
        _exit(1, passed_tests, failed_tests)


def _exit(code, passed, failed):
    log(logging.INFO, "Passed tests", "\n".join(passed))
    log(logging.INFO, "Failed tests", "\n".join(failed))
    exit(code)


def get_path(p):
    return os.path.join(os.path.join(os.path.dirname(__file__), p))


def get_pipeline_input(data):
    return '| from read_text("%s") ' \
           '| select from_json_object(value) as input_event ' \
           '| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null))' % data


def get_pipeline_output(pass_condition):
    return '%s;' % pass_condition


def extract_pipeline(search, data, pass_condition):
    updated_search = re.sub(r"\|\s*from\s+read_ssa_enriched_events\(\s*\)",
                            get_pipeline_input(data),
                            search)
    updated_search = re.sub(r"\|\s*into\s+write_ssa_detected_events\(\s*\)\s*;",
                            get_pipeline_output(pass_condition),
                            updated_search)
    return updated_search


def build_humvee():
    if not os.path.exists(get_path(SSML_CWD)):
        os.mkdir(get_path(SSML_CWD))
    if not os.path.exists(get_path("%s/humvee.jar" % SSML_CWD)):
        logger.debug("Downloading Humvee")
        urllib.request.urlretrieve(HUMVEE_URL, "%s/humvee.jar" % get_path(SSML_CWD))


def activate_detection(detection, data, pass_condition):
    with open(detection, 'r') as fh:
        parsed_detection = yaml.safe_load(fh)
        # Returns pipeline only for SSA detections
        if parsed_detection['type'] == "SSA":

            # validate tags before we run any tests
            # todo add full tag validation via validate_standard_fields from validate.py and move this code block
            # todo into a common file used by both validate.py and validate_ssa.py
            if 'tags' in parsed_detection:
                for k, v in parsed_detection['tags'].items():

                    if k == 'risk_score':
                        if not isinstance(v, int):
                            log(logging.ERROR, "ERROR: risk_score not integer value for object: %s" % v)
                    risk_object_type = ["user", "system", "other"]

                    if k == 'risk_object_type':
                        if v not in risk_object_type:
                            log(logging.ERROR, "ERROR: risk_object_type can only contain user, system, other: %s" % v)

                    if k == 'risk_object':
                        try:
                            v.encode('ascii')
                        except UnicodeEncodeError:
                            log(logging.ERROR, "ERROR: risk_object not ascii for object: %s" % v)

            pipeline = extract_pipeline(parsed_detection['search'], data, pass_condition)
            return pipeline
        else:
            return None


def test_detection(test, args):
    with open(test, 'r') as fh:
        test_desc = yaml.safe_load(fh)
        name = test_desc['name']
        log(logging.INFO, "Testing %s" % name)
        # Download data to temporal folder
        data_dir = tempfile.TemporaryDirectory(prefix="data", dir=get_path("%s" % SSML_CWD))
        # Temporal solution
        if test_desc['attack_data'] is None or len(test_desc['attack_data']) == 0:
            log(logging.ERROR, "No dataset in testing file in %s" % test)
            return False
        d = test_desc['attack_data'][0]
        test_data = os.path.abspath("%s/%s" % (data_dir.name, d['file_name']))
        log(logging.DEBUG, "Downloading dataset %s from %s" % (d['file_name'], d['data']))
        urllib.request.urlretrieve(d['data'], test_data)
        # for d in test_desc['attack_data']:
        #     test_data = "%s/%s" % (data_dir.name, d['file_name'])
        #     urllib.request.urlretrieve(d['data'], test_data)
        for detection in test_desc['detections']:
            detection_file = get_path("../detections/%s" % detection['file'])
            spl2 = activate_detection(detection_file, test_data, detection['pass_condition'])
            if args.debug:
                log(logging.DEBUG, "Test SPL2 query", detail=spl2)
                with open(test_data, 'r') as test_data_fh:
                    log(logging.DEBUG, "Sample testing data", detail="\n".join(test_data_fh.readlines()[:10]))
            if spl2 is not None:
                spl2_file = os.path.join(data_dir.name, "test.spl2")
                test_out = "%s.out" % spl2_file
                test_status = "%s.status" % test_out
                with open(spl2_file, 'w') as spl2_fh:
                    spl2_fh.write(spl2)
                # Execute SPL2
                log(logging.INFO, "Humvee test %s" % detection['name'])
                subprocess.run(["/usr/bin/java",
                                "-jar", get_path("%s/humvee.jar" % SSML_CWD),
                                'cli',
                                '-i', spl2_file,
                                '-o', test_out],
                               stderr=subprocess.DEVNULL)
                # Validate that it can run
                with open(test_status, "r") as test_status_fh:
                    status = '\n'.join(test_status_fh.readlines())
                    if status == "OK\n":
                        log(logging.INFO, "%s executed without issues" % detection['name'])
                    else:
                        log(logging.ERROR, "Detection %s can not be executed" % detection_file, detail=status)
                        log(logging.ERROR, "Faulty SPL2 with errors", detail=spl2)
                        return False
                # Validate the results
                with open(test_out, 'r') as test_out_fh:
                    res = test_out_fh.readlines()
                    log(logging.DEBUG,
                        "Output events sample (%d/%d)" % (len(res[:10]), len(res)),
                        detail="\n".join(res[:10]))
                    if len(res) > 0:
                        log(logging.DEBUG, "Passed test %s" % detection['name'])
                    else:
                        log(logging.ERROR, "Pass condition %s didn't produce any events" % detection['pass_condition'])
                        return False
    return True


if __name__ == '__main__':
    main(sys.argv[1:])
