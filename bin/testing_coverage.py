import yaml
import os
import argparse
import sys

tested = dict()
untested = dict()
coverage = dict()
total_tested = 0
total_untested = 0

def get_path(p):
    return os.path.join(os.path.join(os.path.dirname(__file__), p))


def parse_detection(d):
    with open(d, "r") as fh:
        return yaml.safe_load(fh)


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--min-coverage',
                        type=float,
                        default=0.0,
                        help="Minimum coverage, script return error if target is not met")
    parser.add_argument('--types', type=str, nargs="*", help="SSA, ESCU", default=["ESCU", "SSA"])
    parsed = parser.parse_args(args)
    populate_coverage(parsed.types)
    print_results(parsed.types)
    if total_tested / (total_tested + total_untested) < parsed.min_coverage:
        print("Minimum coverage not met for %s" % ",".join(parsed.types))
        exit(-1)


def populate_coverage(types):
    global total_tested, total_untested
    # Find all tested
    for root, _, files in os.walk(get_path("../tests")):
        for test in files:
            if test.endswith('.yml') or test.endswith('yaml'):
                with open(os.path.join(root, test), 'r') as test_fh:
                    test_desc = yaml.safe_load(test_fh)
                    for t in test_desc['tests']:
                        detection_desc = parse_detection(get_path("../detections/%s" % t['file']))
                        detection_type = detection_desc['type']
                        if detection_type in types:
                            if detection_type not in tested:
                                tested[detection_type] = set()
                            tested[detection_type].add(t['file'])

    for root, _, files in os.walk(get_path("../detections")):
        if not os.path.isfile(os.path.join(root, ".untested")):
            for detection in files:
                if detection.endswith('yml') or detection.endswith('yaml'):
                    detection_desc = parse_detection(os.path.join(root, detection))
                    detection_type = detection_desc['type']
                    if detection_type in types:
                        detection = "%s/%s" % (root.split("/")[-1], detection)
                        if detection not in tested[detection_type]:
                            if detection_type not in untested:
                                untested[detection_type] = list()
                            untested[detection_type].append(detection)

    for k in types:
        n_tested = len(tested[k]) if k in tested else 0
        n_untested = len(untested[k]) if k in untested else 0
        total_tested = total_tested + n_tested
        total_untested = total_untested + n_untested
        coverage[k] = (n_tested, n_tested + n_untested, n_tested / (n_tested + n_untested))


def print_results(types):
    for k in types:
        print('''
Tested %s detections
====================
%s
    ''' % (k, "\n".join(tested[k]) if k in tested else ""))
        print('''
Untested %s detections
======================
%s
    ''' % (k, "\n".join(untested[k]) if k in untested else ""))

    for k in types:
        print("""%s testing coverage: (%d/%d) %.2f"""
              % (k, *coverage[k]))

    print("""Total testing coverage: (%d/%d) %.2f"""
          % (total_tested, total_untested + total_tested, total_tested / (total_tested + total_untested)))



if __name__ == '__main__':
    main(sys.argv[1:])
