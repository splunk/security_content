
import uuid
import sys
import boto3
import argparse


def main(args):

    parser = argparse.ArgumentParser(description="Detection Testing Execution")
    parser.add_argument("-b", "--branch", required=True, help="security content branch")

    args = parser.parse_args()
    branch = args.branch

    # start aws batch job
    client = boto3.client("batch")
    response = client.submit_job(
        jobName='detection_testing',
        jobQueue='detection_testing_execution_queue',
        jobDefinition='AndrewJobDefinition',
        containerOverrides={
            'command': ['-b', branch, '-u', str(uuid.uuid4())]
        }
    )

    # loop dynamo db for results



if __name__ == "__main__":
    main(sys.argv[1:])