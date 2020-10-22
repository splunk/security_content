import yaml
import re
import os
import git
import subprocess
import urllib.request
import tempfile
import argparse
import sys

SSML_CWD = ".splunk-streaming-ml"


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('test_files', type=str, nargs='+', help="test files to be checked")

    parsed = parser.parse_args(args)
    build_humvee()
    for t in parsed.test_files:
        test_detection(t)
    exit(0)


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
        git.Repo.clone_from('git@cd.splunkdev.com:applied-research/splunk-streaming-ml.git',
                            get_path(SSML_CWD))
    else:
        git.cmd.Git(get_path(SSML_CWD)).pull()
    subprocess.run(["./gradlew", "humvee:shadowJar"], cwd=get_path(SSML_CWD))


def activate_detection(detection, data, pass_condition):
    with open(detection, 'r') as fh:
        parsed_detection = yaml.safe_load(fh)
        pipeline = extract_pipeline(parsed_detection['search'], data, pass_condition)
        return pipeline


def test_detection(test):
    with open(test, 'r') as fh:
        test_desc = yaml.safe_load(fh)
        name = test_desc['name']
        print("Testing %s" % name)
        # Download data to temporal folder
        data_dir = tempfile.TemporaryDirectory(prefix="data", dir=get_path("%s/humvee" % SSML_CWD))
        # Temporal solution
        d = test_desc['attack_data'][0]
        test_data = os.path.abspath("%s/%s" % (data_dir.name, d['file_name']))
        urllib.request.urlretrieve(d['data'], test_data)
        # for d in test_desc['attack_data']:
        #     test_data = "%s/%s" % (data_dir.name, d['file_name'])
        #     urllib.request.urlretrieve(d['data'], test_data)
        for detection in test_desc['detections']:
            detection_file = get_path("../detections/%s" % detection['file'])
            spl2 = activate_detection(detection_file, test_data, detection['pass_condition'])
            spl2_file = os.path.join(data_dir.name, "test.spl2")
            test_out = "%s.out" % spl2_file
            test_status = "%s.status" % test_out
            with open(spl2_file, 'w') as spl2_fh:
                spl2_fh.write(spl2)
            # Execute SPL2
            subprocess.run(["java",
                            "-jar", get_path("%s/humvee/build/libs/humvee-1.2.1-SNAPSHOT-all.jar" % SSML_CWD),
                            'cli',
                            '-i', spl2_file,
                            '-o', test_out],
                           stderr=subprocess.DEVNULL)
            # Validate that it can run
            with open(test_status, "r") as test_status_fh:
                status = '\n'.join(test_status_fh.readlines())
                if status == "OK\n":
                    print("SPL2 executed")
                else:
                    print("Errors in detection")
                    print("-------------------")
                    print(status)
                    print("\nTested query from %s:\n" % detection['file'])
                    print(spl2)
                    exit(1)
            # Validate the results
            with open(test_out, 'r') as test_out_fh:
                if len(test_out_fh.readlines()) > 0:
                    print("Output expected")
                else:
                    print("Passing condition %s didn't produce any events" % detection['passing_condition'])
                    exit(1)


if __name__ == '__main__':
    main(sys.argv[1:])
