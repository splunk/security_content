import yaml
import subprocess
import urllib.request
import tempfile
import argparse
from bin_tools.ssa_utils import *

TEST_TIMEOUT = 600


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--skip-errors', action='store_true', default=False)
    parser.add_argument('--debug', action='store_true', default=False)
    parser.add_argument('test_files', type=str, nargs='+', help="test files to be checked")
    parsed = parser.parse_args(args)
    if parsed.debug:
        logger.setLevel(logging.DEBUG)
    build_humvee(get_path(SSML_CWD))
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
    total_passed = len(passed)
    total_failed = len(failed)
    log(logging.INFO, "Passed tests (%d/%d)" % (total_passed, total_passed + total_failed), "\n".join(passed))
    log(logging.INFO, "Failed tests (%d/%d)" % (total_failed, total_passed + total_failed), "\n".join(failed))
    exit(code)


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


def activate_detection(detection, data, pass_condition):
    with open(detection, 'r') as fh:
        parsed_detection = yaml.safe_load(fh)
        # Returns pipeline only for SSA detections
        if parsed_detection['type'] == "SSA":
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
                try:
                    subprocess.run(["/usr/bin/java",
                                    "-jar", get_path("%s/humvee.jar" % SSML_CWD),
                                    'cli',
                                    '-i', spl2_file,
                                    '-o', test_out],
                                   stderr=subprocess.DEVNULL,
                                   timeout=TEST_TIMEOUT)
                except TimeoutError:
                    log(logging.ERROR, "%s test timeout" % detection['name'])
                    return False
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
