# This script is to help set up the dashboard beta app after user installs it to splunk enterprise.
# Specifically, it uploads some icons and images to kvstore, so that user can use them right away.
# This needs to run right after user installs the app, and only runs once.
#
# To debug this script, run a splunk search: index=_internal
# "save_image_and_icon_on_install"
import sys
import logging
import base64
import json
import splunk.rest as rest
from mimetypes import guess_type
from splunk import SplunkdConnectionException
from os import walk
from os.path import join
from splunk.clilib.bundle_paths import get_base_path
from utils import IS_PYTHON_3, strip_uuid

KVSTORE_ENDPOINT = '/servicesNS/nobody/devsecops/storage/collections/data'


def modify_kvstore(folder_name, method, collection_name=None, session_key=None):
    # read files
    folder = join(
        get_base_path(),
        'devsecops',
        'appserver',
        'static',
        folder_name)

    _, _, filenames = walk(folder).__next__() if IS_PYTHON_3 else walk(folder).next()

    visible_filenames = [f for f in filenames if not f[0] == '.']
    
    for filename in visible_filenames:
        file_full_path = join(folder, filename)
        with open(file_full_path, 'rb') as image_file:
            encoded_string = base64.b64encode(image_file.read())
            (image_type, _) = guess_type(file_full_path)
            data_uri = 'data:{};base64,{}'.format(image_type, encoded_string.decode('utf-8') if IS_PYTHON_3 else encoded_string)
            url = KVSTORE_ENDPOINT + '/' + collection_name
            if method == 'POST':
                logging.info(
                    'start saving to kvstore, name is {}, type is {}'.format(
                        filename, image_type))
                payload = {
                    # manually specify _key to avoid random _key, so that pre-built
                    # dashboard can use them
                    '_key': filename,
                    'dataURI': data_uri,
                    'metaData': {
                        'name': strip_uuid(filename)
                    }
                }
                # although kvstore has /batch_save endpoint, we cannot use it
                # because data_uri could be very large that kvstore throws error.
                response, content = rest.simpleRequest(
                    url, sessionKey=session_key, method='POST', jsonargs=json.dumps(payload))
                logging.info(
                    'complete saving to kvstore, response: {}, content: {}'.format(
                        response, content))
            elif method == 'DELETE':
                try:
                    url = url + '/' + filename
                    logging.info(
                        'start deleting from kvstore, name is {}, type is {}'.format(
                            filename, image_type))
                    response, content = rest.simpleRequest(
                        url, sessionKey=session_key, method='DELETE')
                    logging.info(
                        'complete deleting from kvstore, response: {}, content: {}'.format(
                            response, content))
                except Exception as e:
                    logging.error(str(e))
                    logging.error(
                        'Failed to delete icon/image named {} from kvstore.'.format(filename))


if __name__ == '__main__':
    # set up logger to send message to stderr so it will end up in splunkd.log
    sh = logging.StreamHandler()
    # the following line is to make sure the log event looks the same as any
    # other splunkd.log
    sh.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    l = logging.getLogger()
    l.setLevel(logging.INFO)
    l.addHandler(sh)
    try:
        session_key = sys.stdin.readline().strip()
        modify_kvstore(
            folder_name='images',
            method='DELETE',
            collection_name='devsecops-images',
            session_key=session_key)
        modify_kvstore(
            folder_name='images',
            method='POST',
            collection_name='devsecops-images',
            session_key=session_key)
    except SplunkdConnectionException:
        logging.error(str(e))
        logging.error('Failed to connect to splunkd.')
        exit(1)
    except Exception as e:
        logging.error(str(e))
        logging.error(
            'Failed to save images and icons to kvstore due to an error.')
        exit(1)
