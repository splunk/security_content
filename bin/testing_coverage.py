import yaml
import os


def get_path(p):
    return os.path.join(os.path.join(os.path.dirname(__file__), p))


def parse_detection(d):
    with open(d, "r") as fh:
        return yaml.safe_load(fh)


tested = dict()
untested = dict()


# Find all tested
for root, _, files in os.walk(get_path("../tests")):
    for test in files:
        if test.endswith('.yml') or test.endswith('yaml'):
            with open(os.path.join(root, test), 'r') as test_fh:
                test_desc = yaml.safe_load(test_fh)
                for t in test_desc['detections']:
                    detection_desc = parse_detection(get_path("../detections/%s" % t['file']))
                    detection_type = detection_desc['type']
                    if detection_type not in tested:
                        tested[detection_type] = set()
                    tested[detection_type].add(t['file'])

for root, _, files in os.walk(get_path("../detections")):
    if not os.path.isfile(os.path.join(root, ".untested")):
        for detection in files:
            if detection.endswith('yml') or detection.endswith('yaml'):
                detection_desc = parse_detection(os.path.join(root, detection))
                detection_type = detection_desc['type']
                detection = "%s/%s" % (root.split("/")[-1], detection)
                if detection not in tested[detection_type]:
                    if detection_type not in untested:
                        untested[detection_type] = list()
                    untested[detection_type].append(detection)


for k in set(untested.keys()).union(tested.keys()):
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

total_tested = 0
total_untested = 0
for k in set(untested.keys()).union(tested.keys()):
    n_tested = len(tested[k]) if k in tested else 0
    n_untested = len(untested[k]) if k in untested else 0
    total_tested = total_tested + n_tested
    total_untested = total_untested + n_untested
    print("""%s testing coverage: (%d/%d) %.2f"""
          % (k, n_tested, n_tested + n_untested, n_tested / (n_tested + n_untested)))

print("""Total testing coverage: (%d/%d) %.2f"""
      % (total_tested, total_untested + total_tested, total_tested / (total_tested + total_untested)))