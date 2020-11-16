import yaml
import argparse
import tempfile
import subprocess
from modules.ssa_utils import *


DUMB_PIPELINE_INPUT = '| from read_text("/")' \
                      '| select from_json_object(value) as input_event' \
                      '| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null))'

DUMB_PIPELINE_OUTPUT = ';'


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
    for t in parsed.detection_files:
        cur_status = validate_required_fields(t)
        status = status & cur_status
        if cur_status:
            passed_validations.append(t)
        else:
            failed_validations.append(t)
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
    data_dir = tempfile.TemporaryDirectory(prefix="data", dir=get_path("%s" % SSML_CWD))
    pipeline_file = os.path.join(data_dir.name, "test.spl2")
    fields_file = os.path.join(data_dir.name, "fields.out")
    write_validation_pipeline(spl2, pipeline_file)
    subprocess.run(["/usr/bin/java",
                    "-jar", get_path("%s/humvee.jar" % SSML_CWD),
                    'cli', '-i',
                    pipeline_file, '-o',
                    fields_file,
                    '-f'],
                   stderr=subprocess.DEVNULL,
                   check=True)
    spl2_ssa_fields = set()
    with open(fields_file, 'r') as test_out_fh:
        for f in test_out_fh.readlines():
            spl2_ssa_fields.add(f.strip())
    return spl2_ssa_fields


def validate_tags(detection):
    if 'tags' not in detection:
        log(logging.ERROR, "Missing `tags` from detection %s" % detection['name'])
        return False
    if 'risk_severity' not in detection['tags']:
        log(logging.ERROR, "Missing `risk_severity` tag from detection `tags` in %s" % detection['name'])
        return False
    return True


def validate_required_fields(detection_file):
    if os.path.isfile(detection_file):
        with open(detection_file, 'r') as detection_fh:
            detection = yaml.safe_load(detection_fh)
            if detection['type'] == "SSA":
                if not validate_tags(detection):
                    return False
                try:
                    spl2_ssa_fields = extract_ssa_fields(detection['search'])
                    log(logging.DEBUG, "SSA fields used by the detection", detail=",".join(spl2_ssa_fields))
                    if "required_fields" not in detection['tags']:
                        log(logging.ERROR,
                            "required_fields not present in detection %s" % detection_file,
                            detail='''Suggested action: Append this to "tags" in your detection
                    %s''' % yaml.dump({'required_fields': list(spl2_ssa_fields)}))
                        return False
                    declared_ssa_fields = set(detection['tags']['required_fields'])
                    fields_declared_not_used = declared_ssa_fields.difference(spl2_ssa_fields)
                    fields_not_declared = spl2_ssa_fields.difference(declared_ssa_fields)
                    if len(fields_declared_not_used) > 0:
                        log(logging.ERROR,
                            "Some declared fields in detection %s not used in pipeline" % detection_file,
                            detail=','.join(fields_declared_not_used))
                        return False
                    if len(fields_not_declared) > 0:
                        log(logging.ERROR,
                            "Some fields used in the pipeline not declared in detection %s" % detection_file,
                            detail=','.join(fields_not_declared))
                        return False
                    return True
                except subprocess.CalledProcessError:
                    log(logging.ERROR, "Syntax errors in pipeline %s" % detection_file, detail=detection['search'])
                    return False
            else:
                log(logging.DEBUG, "Not a SSA detection", detail=detection_file)
                return True
    return True

if __name__ == '__main__':
    main(sys.argv[1:])
