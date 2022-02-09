import yaml
import sys
import argparse
import tempfile
import subprocess
from modules.ssa_utils import *
from modules.testing_utils import *


DUMB_PIPELINE_INPUT = '| from read_text("test.spl2")' \
                      '| select from_json_object(value) as input_event' \
                      '| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null))'

DUMB_PIPELINE_OUTPUT = '| select start_time, end_time, entities, body;'


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--skip-errors', action='store_true', default=False)
    parser.add_argument('--debug', action='store_true', default=False)
    parser.add_argument('detection_files', type=str, nargs='+', help="detection files to be checked")
    parsed = parser.parse_args(args)
    if parsed.debug:
        logger.setLevel(logging.DEBUG)
    build_humvee(get_path(SSML_CWD))
    status = True
    passed_validations = []
    failed_validations = []
    for detection_file in parsed.detection_files:
        if os.path.isfile(detection_file):
            with open(detection_file, 'r') as detection_fh:
                detection = yaml.safe_load(detection_fh)
                if detection['type'] == "streaming":
                    # Parsed file is a SSA detection
                    log(logging.INFO, "Validating %s" % detection['name'])
                    cur_status = validate_tags(detection)
                    cur_status = cur_status & validate_required_fields(detection)
                    status = status & cur_status
                    if cur_status:
                        passed_validations.append(detection_file)
                    else:
                        failed_validations.append(detection_file)
                    if not status and not parsed.skip_errors:
                        exit(1)
    if status:
        exit(0)
    else:
        exit(1)


def write_validation_pipeline(spl2, spl2_file):
    pipeline = re.sub(r"\|\s*from\s+read_ssa_enriched_events\(\s*\)",
                      DUMB_PIPELINE_INPUT,
                      spl2)
    pipeline = re.sub(r"\|\s*into\s+write_ssa_detected_events\(\s*\)\s*;",
                      DUMB_PIPELINE_OUTPUT,
                      pipeline)
    with open(spl2_file, 'w') as spl2_fh:
        spl2_fh.write(pipeline)
    log(logging.DEBUG, "Testing SPL2 pipeline", detail=pipeline)


def extract_ssa_fields(spl2):
    """
    From a SPL2 pipeline extracts SSA fields using Humvee
    @param spl2: String representing the pipeline search
    @return: A set of fields used in the pipeline
    """
    data_dir = tempfile.TemporaryDirectory(prefix="data", dir=get_path("%s" % SSML_CWD))
    pipeline_file = os.path.join(data_dir.name, "test.spl2")
    fields_file = os.path.join(data_dir.name, "fields.out")
    write_validation_pipeline(spl2, pipeline_file)
    subprocess.run(["/usr/bin/java",
                    "-jar", "humvee.jar",
                    'cli', '-i',
                    pipeline_file, '-o',
                    fields_file,
                    '-f'],
                   #stderr=subprocess.DEVNULL,
                   cwd=get_path(SSML_CWD),
                   check=True)
    spl2_ssa_fields = set()
    with open(fields_file, 'r') as test_out_fh:
        for f in test_out_fh.readlines():
            spl2_ssa_fields.add(f.strip())
    return spl2_ssa_fields


def validate_tags(detection):
    """
    Checks that some generic tags have been populated
    @param detection: Parsed YAML dictionary of a SSA detection file
    @return: True when tags are present
    """
    if 'tags' not in detection:
        log(logging.ERROR, "Missing `tags` from detection %s" % detection['name'])
        return False
    if 'risk_severity' not in detection['tags']:
        log(logging.ERROR, "Missing `risk_severity` tag from detection `tags` in %s" % detection['name'])
        return False
    return validate_required_fields(detection)


def validate_required_fields(detection):
    """
    Checks that required fields has been populated in the required tags.
    If there are issues it reports them to the log ERROR console
    @param detection: Parsed YAML dictionary of a SSA detection file
    @return: True when declared fields are consistent with the search
    """
    try:
        spl2_ssa_fields = extract_ssa_fields(detection['search'])
        log(logging.DEBUG, "SSA fields used by the detection", detail=",".join(spl2_ssa_fields))
        if "required_fields" not in detection['tags']:
            log(logging.ERROR,
                "required_fields not present in detection %s" % detection['name'],
                detail='''Suggested action: Append this to "tags" in your detection
        %s''' % yaml.dump({'required_fields': list(spl2_ssa_fields)}))
            return False
        declared_ssa_fields = set(detection['tags']['required_fields'])
        fields_declared_not_used = declared_ssa_fields.difference(spl2_ssa_fields)
        fields_not_declared = spl2_ssa_fields.difference(declared_ssa_fields)
        if len(fields_declared_not_used) > 0:
            log(logging.ERROR,
                "Some declared fields in detection %s not used in pipeline" % detection['name'],
                detail=','.join(fields_declared_not_used))
            return False
        if len(fields_not_declared) > 0:
            log(logging.ERROR,
                "Some fields used in the pipeline not declared in detection %s" % detection['name'],
                detail=','.join(fields_not_declared))
            return False
        return True
    except subprocess.CalledProcessError:
        log(logging.ERROR,
            "Syntax errors in pipeline %s" % detection['name'],
            detail=detection['search'])
        log(logging.INFO, "Perhaps required [input|output] fields do not match SSA ones")
    return False


if __name__ == '__main__':
    main(sys.argv[1:])
