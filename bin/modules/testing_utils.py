import os
import sys
import logging
import coloredlogs
import urllib.request
import yaml

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(coloredlogs.ColoredFormatter("%(asctime)s - %(levelname)s - %(message)s%(detail)s"))
logger.addHandler(handler)


def get_path(p):
    return os.path.join(os.path.join(os.path.dirname(__file__), "..", p))


def log(level, msg, detail=None):
    args = {'detail': ""} if detail is None else {'detail': "\n%s" % detail}
    logger.log(level, msg, extra=args)


def get_detection(unit_test):
    with open(get_path("../detections/%s" % unit_test['file'])) as detection_fh:
        parsed_detection = yaml.safe_load(detection_fh)
        return parsed_detection


def pull_data(test, destination):
    data_desc = dict()
    if 'attack_data' in test:
        for d in test['attack_data']:
            test_data = "%s/%s" % (destination, d['file_name'])
            urllib.request.urlretrieve(d['data'], test_data)
            data_desc[d['file_name']] = test_data
            log(logging.DEBUG, "Downloading dataset %s from %s" % (d['file_name'], d['data']))
    return data_desc
