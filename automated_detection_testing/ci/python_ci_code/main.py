
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

    # vars
    max_waiting_time = 3600
    current_waiting_time = 0

    # create uuid 
    uuid_test = str(uuid.uuid4())

    # start aws batch job
    # client = boto3.client("batch", region_name="eu-central-1")
    # response = client.submit_job(
    #     jobName='detection_testing',
    #     jobQueue='detection_testing_execution_queue',
    #     jobDefinition='detection_testing_execution:2',
    #     containerOverrides={
    #         'command': ['-b', branch, '-u', uuid_test]
    #     }
    # )

    dynamodb = boto3.client('dynamodb', region_name="eu-central-1")
    response = dynamodb.query(
        TableName='dt-results',
        IndexName='uuid_test-index',
        KeyConditionExpression='uuid_test = :uuid_test',
        ExpressionAttributeValues={
                ':uuid_test': {'S': '3a8b5ea8-2f89-4006-b684-8e7e564f4047'}
        }
    )
    print(response['Items'])


    # resource = boto3.resource('dynamodb', region_name="eu-central-1")
    # table = resource.Table("dt-results")

    # response = table.get_item(
    #     Key={
    #         'uuid_test': uuid_test
    #     }
    # )

    # print(response)


    # while max_waiting_time > current_waiting_time:

    #     response = table.get_item(
    #         Key={
    #             'uuid_test': uuid_test
    #         }
    #     )

    #     if len(response['Items']) == 0:
    #         time.sleep(60)
    #         current_waiting_time = current_waiting_time + 60
    #     else:
            # iterate through results




if __name__ == "__main__":
    main(sys.argv[1:])

