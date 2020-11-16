import os
import sys
import json
import hashlib
import urllib.request
import re
import logging
import coloredlogs

SSML_CWD = ".humvee"
HUMVEE_ARTIFACT_SEARCH = "https://repo.splunk.com/artifactory/api/search/artifact?name=humvee&repos=maven-splunk-local"


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


def get_latest_humvee_object():
    res = json.loads(urllib.request.urlopen(HUMVEE_ARTIFACT_SEARCH).read().decode('utf-8'))
    for r in res['results']:
        if re.match(r".*/latest/humvee-.*\.jar$", r['uri']):
            latest_humvee = json.loads(urllib.request.urlopen(r['uri']).read().decode('utf-8'))
            return latest_humvee
    return ""


def build_humvee(path):
    if not os.path.exists(path):
        os.mkdir(path)
    latest_humvee_object = get_latest_humvee_object()
    humvee_path = "%s/humvee.jar" % path
    humvee_md5 = ""
    if os.path.exists(humvee_path):
        with open(humvee_path, 'rb') as jar_fh:
            humvee_md5 = hashlib.md5(jar_fh.read()).hexdigest()
            log(logging.DEBUG, "Current local checksum of Humvee", detail=humvee_md5)
    if humvee_md5 != latest_humvee_object['checksums']['md5']:
        log(logging.INFO, "Downloading Latest Humvee")
        log(logging.DEBUG, "Humvee details", detail=latest_humvee_object)
        urllib.request.urlretrieve(latest_humvee_object['downloadUri'], humvee_path)
    else:
        log(logging.DEBUG, "Already latest checksum %s" % humvee_md5, detail=latest_humvee_object)