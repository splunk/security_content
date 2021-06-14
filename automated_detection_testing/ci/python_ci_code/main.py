
import uuid
import sys
import boto3
import argparse
import time


def main(args):

    parser = argparse.ArgumentParser(description="Detection Testing Execution")
    parser.add_argument("-b", "--branch", required=True, help="security content branch")

    args = parser.parse_args()
    branch = args.branch

    # create uuid 
    uuid_test = str(uuid.uuid4())

    # start aws batch job
    client = boto3.client("batch", region_name="eu-central-1")
    response = client.submit_job(
        jobName='detection_testing',
        jobQueue='detection_testing_execution_queue',
        jobDefinition='detection_testing_execution:2',
        containerOverrides={
            'command': ['-b', branch, '-u', uuid_test]
        }
    )

    resource = boto3.resource('dynamodb', region_name="eu-central-1")
    table = resource.Table("dt-results")
    response = table.get_item(
        Key={
            'uuid_test': uuid_test
        }
    )
    print(response)



if __name__ == "__main__":
    main(sys.argv[1:])

