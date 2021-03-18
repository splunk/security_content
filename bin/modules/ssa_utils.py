import os
import json
import hashlib
import urllib.request
import re
import logging
from modules.testing_utils import log

SSML_CWD = ".humvee"
HUMVEE_ARTIFACT_SEARCH = "https://repo.splunk.com/artifactory/api/search/artifact?name=humvee&repos=maven-splunk-local"


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


#def convert_to_ssa(detection):
#    '''
#    curl -H 'Content-type: text/yaml' -H 'Authorization: Bearer TOKEN'
#    https://app-admin.playground.scp.splunk.com/secanalytics/ssa-tenant-management/v1alpha1/admin/detection-spl/research2
#    --data-binary @detections/endpoint/ssa___first_time_seen_cmd_line.yml
#    @param detection:
#    @return:
#    '''
