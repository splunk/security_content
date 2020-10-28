import yaml
import os


def get_path(p):
    return os.path.join(os.path.join(os.path.dirname(__file__), p))


def parse_detection(d):
    with open(d, "r") as fh:
        return yaml.safe_load(fh)


tested = set()
untested = list()


# Find all tested
for root, _, files in os.walk(get_path("../tests")):
    for test in files:
        if test.endswith('.yml') or test.endswith('yaml'):
            with open(os.path.join(root, test), 'r') as test_fh:
                test_desc = yaml.safe_load(test_fh)
                for t in test_desc['detections']:
                    detection_desc = parse_detection(get_path("../detections/%s" % t['file']))
                    if detection_desc['type'] == 'SSA':
                        tested.add(t['file'])

for root, _, files in os.walk(get_path("../detections")):
    for detection in files:
        if detection.endswith('yml') or detection.endswith('yaml'):
            detection_desc = parse_detection(os.path.join(root, detection))
            if detection_desc['type'] == 'SSA':
                detection = "%s/%s" % (root.split("/")[-1], detection)
                if detection not in tested:
                    untested.append(detection)

print('''
Tested detections
=================
%s
''' % "\n".join(tested))

print('''
Untested detections
===================
%s
''' % "\n".join(untested))