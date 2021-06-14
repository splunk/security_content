import boto3




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


def add_detection_results_in_dynamo_db(region, uuid, uuid_test, detection, detection_path, result, time):
    resource = boto3.resource('dynamodb', region_name=region)
    table = resource.Table("dt-results")
    response = table.put_item(Item= {
        'uuid': uuid, 
        'uuid_test': uuid_test,
        'detection': detection, 
        'detection_path': detection_path,
        'result': result,
        'time': time
    })