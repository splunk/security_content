
import uuid
import sys
import boto3
import argparse
import time


def main(args):

    parser = argparse.ArgumentParser(description="Detection Testing Execution")
    parser.add_argument("-b", "--branch", required=True, help="security content branch")
    parser.add_argument("-pr", "--pr-number", required=False, help="Pull Request Number")

    args = parser.parse_args()
    branch = args.branch
    pr_number = args.pr_number

    # vars
    max_waiting_time = 7200
    current_waiting_time = 0

    # create uuid 
    uuid_test = str(uuid.uuid4())

    # start aws batch job
    client = boto3.client("batch", region_name="eu-central-1")

    if pr_number:
        response = client.submit_job(
            jobName='detection_testing_' + branch,
            jobQueue='detection_testing_execution_queue',
            jobDefinition='detection_testing_execution:2',
            containerOverrides={
                'command': ['-b', branch, '-u', uuid_test, '-pr', pr_number]
            }
        )
    else:
        response = client.submit_job(
            jobName='detection_testing_' + branch,
            jobQueue='detection_testing_execution_queue',
            jobDefinition='detection_testing_execution:2',
            containerOverrides={
                'command': ['-b', branch, '-u', uuid_test]
            }
        )


    while max_waiting_time > current_waiting_time:

        dynamodb = boto3.client('dynamodb', region_name="eu-central-1")
        response = dynamodb.query(
            TableName='dt-results',
            IndexName='uuid_test-index',
            KeyConditionExpression='uuid_test = :uuid_test',
            ExpressionAttributeValues={
                    ':uuid_test': {'S': uuid_test}
            }
        )        


        test_done = True
        for item in response['Items']:
            if item['status']['S'] == 'nothing to test':
                print('No new or changed detections to test.')
                sys.exit(0)

            if item['status']['S'] == 'running':
                test_done = False

        if len(response['Items']) == 0 or (not test_done):
            time.sleep(60)
            current_waiting_time = current_waiting_time + 60
        else:
            test_passed = True
            for item in response['Items']:
                if item['result']['S'] == 'failed':
                    test_passed = False
                    print('Test failed for detection: ' + item['detection']['S'] + ', ' + item['detection_path']['S'])
                else:
                    print('Test passed for detection: ' + item['detection']['S'] + ', ' + item['detection_path']['S'])
            sys.exit(not test_passed)

    sys.exit(1)



if __name__ == "__main__":
    main(sys.argv[1:])

