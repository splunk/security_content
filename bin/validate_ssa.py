import yaml
import re
import os
import git
import subprocess
import urllib.request
import tempfile

ssml_cwd = ".splunk-streaming-ml"

def get_path(p):
    return os.path.join(os.path.join(os.path.dirname(__file__), p))


def get_pipeline_input(data):
    return '| from read_text("%s") ' \
           '| select from_json_object(value) as input_event ' \
           '| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null))' % data


def get_pipeline_output():
    return ';'


def extract_pipeline(search, data):
    updated_search = re.sub(r"\|\s*from\s+read_ssa_enriched_events\(\s*\)", get_pipeline_input(data), search)
    updated_search = re.sub(r"\|\s*into\s+write_ssa_detected_events\(\s*\)\s*;", get_pipeline_output(), updated_search)
    return updated_search


def build_humvee():
    if not os.path.exists(get_path(ssml_cwd)):
        git.Repo.clone_from('git@cd.splunkdev.com:applied-research/splunk-streaming-ml.git',
                            get_path(ssml_cwd))
    else:
        git.cmd.Git(get_path(ssml_cwd)).pull()
    subprocess.run(["./gradlew", "humvee:shadowJar"], cwd=get_path(ssml_cwd))


def activate_detection(detection, data):
    with open(detection, 'r') as fh:
        parsed_detection = yaml.safe_load(fh)
        pipeline = extract_pipeline(parsed_detection['search'], data)
        return pipeline


def test_detection(test):
    with open(test, 'r') as fh:
        test_desc = yaml.safe_load(fh)
        name = test_desc['name']
        print("Testing %s" % name)
        # Download data to temporal folder
        data_dir = tempfile.TemporaryDirectory(prefix="data", dir=get_path("%s/humvee" % ssml_cwd))
        print("Temporal data dir %s" % data_dir.name)
        # Temporal solution
        d = test_desc['attack_data'][0]
        test_data = os.path.abspath("%s/%s" % (data_dir.name, d['file_name']))
        urllib.request.urlretrieve(d['data'], test_data)
        # for d in test_desc['attack_data']:
        #     test_data = "%s/%s" % (data_dir.name, d['file_name'])
        #     urllib.request.urlretrieve(d['data'], test_data)
        detection = get_path("../detections/%s" % test_desc['detections'][0]['file'])
        spl2 = activate_detection(detection, test_data)
        spl2_file = os.path.join(data_dir.name, "test.spl2")
        test_out = "%s.out" % spl2_file
        test_status = "%s.status" % test_out
        with open(spl2_file, 'w') as spl2_fh:
            spl2_fh.write(spl2)
        # Execute SPL2
        subprocess.run(["java",
                        "-jar",  get_path("%s/humvee/build/libs/humvee-1.2.1-SNAPSHOT-all.jar" % ssml_cwd),
                        'cli',
                        '-i', spl2_file,
                        '-o', test_out],
                       stderr=subprocess.DEVNULL)
        with open(test_status, "r") as test_status_fh:
            res = '\n'.join(test_status_fh.readlines())
            if res == "OK\n":
                print("SPL2 executed correctly")
                exit(0)
            else:
                print("Errors in detection")
                print("-------------------")
                print(res)
                exit(1)




def deploy_dsp():
    if not os.path.exists(get_path(".data-pipelines")):
        git.Repo.clone_from('git@cd.splunkdev.com:data-availability/data-pipelines.git',
                            get_path('.data-pipelines'))
    else:
        git.cmd.Git(get_path(".data-pipelines")).pull()


print(get_path(ssml_cwd))
build_humvee()
test_detection(get_path("../tests/endpoint/rare_parent_process_relationship_lolbas___ssa.test.yaml"))
