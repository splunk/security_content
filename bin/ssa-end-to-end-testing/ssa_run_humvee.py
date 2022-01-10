from pathlib import Path
import sys
import yaml
import subprocess
import tempfile
import argparse
from modules.ssa_utils import *
from modules.testing_utils import log, logger, get_detection, get_path, pull_data
from ssa_test import extract_pipeline


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('detection_file', type=str, help='detection yaml to be run')
    parser.add_argument('data_file', type=str, help='data json to be fed to the detection')
    opts = parser.parse_args(args)

    humvee_path = Path(os.path.dirname(__file__)) / '.humvee' / 'humvee.jar'
    assert humvee_path.exists()

    data_path = Path(opts.data_file)
    assert data_path.exists()

    detection_path = Path(opts.detection_file)
    assert detection_path.exists()

    with open(detection_path, 'rt') as f:
        detection = yaml.safe_load(f)

    spl2 = extract_pipeline(detection['search'], data_path, None)
    detection_spl_path = Path('/tmp') / (detection['id'] + '.spl2')
    with open(detection_spl_path, 'wt') as f:
        f.write(spl2)

    print('write spl2 to %s' % detection_spl_path)

    subprocess.run(["/usr/bin/java",
                    "-jar", humvee_path,
                    'cli',
                    '-i', detection_spl_path,
                    '-o', 'test.out'])




if __name__ == '__main__':
    main(sys.argv[1:])