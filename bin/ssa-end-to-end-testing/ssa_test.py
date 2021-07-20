import sys
import yaml
import subprocess
import tempfile
import argparse
from modules.ssa_utils import *
from modules.testing_utils import log, logger, get_detection, get_path, pull_data
from modules.assertions import assertions_parser

TEST_TIMEOUT = 600
PASSED = 1
SKIPPED = 0
FAILED = -1


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
    skipped_tests = []
    failed_tests = []
    for t in parsed.test_files:
        cur_status = test_detection(t, parsed)
        status = status and (cur_status == PASSED or cur_status == SKIPPED)
        if cur_status == PASSED:
            passed_tests.append(t)
        elif cur_status == SKIPPED:
            skipped_tests.append(t)
        else:
            failed_tests.append(t)
        if not status and not parsed.skip_errors:
            _exit(1, passed_tests, skipped_tests, failed_tests)
    if status:
        _exit(0, passed_tests, skipped_tests, failed_tests)
    else:
        _exit(1, passed_tests, skipped_tests, failed_tests)


def _exit(code, passed, skipped, failed):
    total_passed = len(passed)
    total_failed = len(failed)
    log(logging.DEBUG, "Skipped tests %d" % len(skipped), "\n".join(skipped))
    log(logging.INFO, "Passed tests (%d/%d)" % (total_passed, total_passed + total_failed), "\n".join(passed))
    log(logging.INFO, "Failed tests (%d/%d)" % (total_failed, total_passed + total_failed), "\n".join(failed))
    exit(code)


def get_pipeline_input(data):
    return '| from read_text("%s") ' \
           '| select from_json_object(value) as input_event ' \
           '| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null))' % data


def extract_pipeline(search, data, pass_condition):
    updated_search = re.sub(r"\|\s*from\s+read_ssa_enriched_events\(\s*\)",
                            get_pipeline_input(data),
                            search)
    updated_search = re.sub(r"\|\s*into\s+write_ssa_detected_events\(\s*\)\s*;",
                            ";",
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
            log(logging.WARN, "Not a SSA. It will be skipped.", parsed_detection['name'])
            return None


def assert_results(pass_condition, events):
    if len(pass_condition) == 0:
        log(logging.ERROR, "Empty pass_condition")
        return False
    try:
        lexer = assertions_parser.AssertionLexer()
        parser = assertions_parser.AssertionParser(events)
        return parser.parse(lexer.tokenize(pass_condition))
    except SyntaxError:
        log(logging.ERROR, "pass_condition not in a language that assert_result can understand", pass_condition)
    return False


def test_detection(test, args):
    with open(test, 'r') as fh:
        test_desc = yaml.safe_load(fh)
        if (test_desc is not None) and ('name' in test_desc) and ('tests' in test_desc):
            name = test_desc['name']
            # Download data to temporal folder
            for unit in test_desc['tests']:
                detection = get_detection(unit)
                if detection['type'] == 'streaming':
                    log(logging.INFO, "Testing %s" % name)
                    # Prepare data
                    data_dir = tempfile.TemporaryDirectory(prefix="data", dir=get_path("%s" % SSML_CWD))
                    detection_file = get_path("../detections/%s" % unit['file'])
                    if unit['attack_data'] is None or len(unit['attack_data']) == 0:
                        log(logging.ERROR, "No dataset in testing file in %s" % test)
                        return FAILED
                    test_data = pull_data(unit, data_dir.name)
                    # Extract pipeline and remove SSA decorations
                    input_data = test_data[list(test_data.keys())[0]]
                    spl2 = extract_pipeline(detection['search'], input_data, unit['pass_condition'])
                    if args.debug:
                        log(logging.DEBUG, "Test SPL2 query", detail=spl2)
                        # will use always the same data file. Still we can't handle multiple datasets in desc file
                        with open(input_data, 'r') as test_data_fh:
                            log(logging.DEBUG, "Sample testing data", detail="\n".join(test_data_fh.readlines()[:10]))
                    if spl2 is not None:
                        # Preparing Execution
                        spl2_file = os.path.join(data_dir.name, "test.spl2")
                        test_out = "%s.out" % spl2_file
                        test_status = "%s.status" % test_out
                        with open(spl2_file, 'w') as spl2_fh:
                            spl2_fh.write(spl2)
                        # Execute SPL2
                        log(logging.INFO, "Humvee test %s" % unit['name'])
                        try:
                            subprocess.run(["/usr/bin/java",
                                            "-jar", get_path("%s/humvee.jar" % SSML_CWD),
                                            'cli',
                                            '-i', spl2_file,
                                            '-o', test_out],
                                           stderr=subprocess.DEVNULL,
                                           timeout=TEST_TIMEOUT)
                        except TimeoutError:
                            log(logging.ERROR, "%s test timeout" % unit['name'])
                            return FAILED
                    # Validate that it can run
                    with open(test_status, "r") as test_status_fh:
                        status = '\n'.join(test_status_fh.readlines())
                        if status == "OK\n":
                            log(logging.INFO, "%s executed without issues" % unit['name'])
                        else:
                            log(logging.ERROR, "Detection %s can not be executed" % detection_file, detail=status)
                            log(logging.ERROR, "Faulty SPL2 with errors", detail=spl2)
                            return FAILED
                    # Validate the results
                    with open(test_out, 'r') as test_out_fh:
                        res = test_out_fh.readlines()
                        log(logging.DEBUG,
                            "Output events sample (%d/%d)" % (len(res[:10]), len(res)),
                            detail="\n".join(res[:10]))
                        if assert_results(unit['pass_condition'], res):
                            log(logging.DEBUG, "Passed test %s" % unit['name'])
                        else:
                            log(logging.ERROR, "Did not pass condition:", unit['pass_condition'])
                            return FAILED
                else:
                    log(logging.DEBUG, "Not an SSA test, skipping testing file", unit['name'])
                    return SKIPPED
        else:
            log(logging.WARN, "Not a testing file", test)
            return SKIPPED
    return PASSED


if __name__ == '__main__':
    main(sys.argv[1:])
