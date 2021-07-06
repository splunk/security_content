import boto3
import uuid



def get_ar_information_from_dynamo_db(region, db_name):
    resource = boto3.resource('dynamodb', region_name=region)
    table = resource.Table(db_name)
    response = table.get_item(
        Key={
            'name': 'detection-testing-attack-range'
        }
    )
    if 'Item' in response:
        return response['Item']
    else:
        return {}


def get_splunk_instance(region, key_name):
    client = boto3.client('ec2', region_name=region)
    response = client.describe_instances(
        Filters=[
            {
                'Name': "key-name",
                'Values': [key_name]
            }
        ]
    )
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if instance['State']['Name']!='terminated':
                if len(instance['Tags']) > 0:
                    tag = instance['Tags'][0]['Value']
                    if key_name in tag:
                        return instance

    return {}


def dynamo_db_nothing_to_test(region, uuid_test, time):
    uuid_var = str(uuid.uuid4())
    resource = boto3.resource('dynamodb', region_name=region)
    table = resource.Table("dt-results")
    response = table.put_item(Item= {
        'uuid': uuid_var, 
        'uuid_test': uuid_test,
        'time': time,
        'status': 'nothing to test'
    })  


def add_detection_results_in_dynamo_db(region, uuid, uuid_test, detection, detection_path, time):
    resource = boto3.resource('dynamodb', region_name=region)
    table = resource.Table("dt-results")
    response = table.put_item(Item= {
        'uuid': uuid, 
        'uuid_test': uuid_test,
        'detection': detection, 
        'detection_path': detection_path,
        'time': time,
        'status': 'running'
    })


def update_detection_results_in_dynamo_db(region, uuid, result):
    resource = boto3.resource('dynamodb', region_name=region)
    table = resource.Table("dt-results")
    response = table.update_item(
        Key={
            'uuid': uuid
        },
        UpdateExpression="set #ts=:s",
        ExpressionAttributeValues={
            ':s': 'done'
        },
        ExpressionAttributeNames={
            "#ts": "status"
        },
        ReturnValues="UPDATED_NEW"
    )

    response = table.update_item(
        Key={
            'uuid': uuid
        },
        UpdateExpression="set #ts=:s",
        ExpressionAttributeValues={
            ':s': result
        },
        ExpressionAttributeNames={
            "#ts": "result"
        },
        ReturnValues="UPDATED_NEW"
    )     