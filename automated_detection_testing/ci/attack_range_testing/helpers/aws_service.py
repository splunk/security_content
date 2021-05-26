import boto3
from botocore.config import Config
import time
import os
import json


def create_entry_database(region, honeypot_name, state):
    resource = boto3.resource('dynamodb', region_name="eu-central-1")
    table = resource.Table("attack_range_honeypot")
    response = table.put_item(Item= {
        'name': honeypot_name, 
        'region': region, 
        'status': state
    })


def update_entry_database(honeypot_name, password, state):
    resource = boto3.resource('dynamodb', region_name="eu-central-1")
    table = resource.Table("attack_range_honeypot")
    response = table.update_item(
        Key={
            'name': honeypot_name
        },
        UpdateExpression="set #ts=:s, password=:p",
        ExpressionAttributeValues={
            ':s': state,
            ':p': password
        },
        ExpressionAttributeNames={
            "#ts": "status"
        },
        ReturnValues="UPDATED_NEW"
    )   


def delete_entry_database(honeypot_name):
    resource = boto3.resource('dynamodb', region_name="eu-central-1")
    table = resource.Table("attack_range_honeypot")
    response = table.delete_item(
        Key={
            'name': honeypot_name
        }
    )


def get_entry_database(honeypot_name):
    resource = boto3.resource('dynamodb', region_name="eu-central-1")
    table = resource.Table("attack_range_honeypot")
    response = table.get_item(
        Key={
            'name': honeypot_name
        }
    )
    if 'Item' in response:
        return response['Item']
    else:
        return {}


def create_tf_state_store(honeypot_name, region):
    my_config = Config(region_name = region)
    s3 = boto3.client('s3', config=my_config)
    response = s3.create_bucket(Bucket=str('attack-range-detection-testing-bucket-' + honeypot_name), CreateBucketConfiguration={'LocationConstraint': region})

    client = boto3.client('dynamodb', config=my_config)
    response = client.create_table(
        TableName=str('attack-range-detection-testing-state-' + honeypot_name),
        KeySchema=[
            {
                'AttributeName': 'LockID',
                'KeyType': 'HASH'  # Partition key
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'LockID',
                'AttributeType': 'S'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 10,
            'WriteCapacityUnits': 10
        }
    )
    

def delete_tf_state_store(region, honeypot_name):
    s3 = boto3.resource('s3', region_name=region)
    bucket = s3.Bucket(str('attack-range-detection-testing-bucket-' + honeypot_name))
    bucket.objects.all().delete()
    bucket.delete()

    dynamodb = boto3.resource('dynamodb', region_name=region)
    table = dynamodb.Table(str('attack-range-detection-testing-state-' + honeypot_name))
    table.delete()


def get_secret(secret_name):
    region_name = "eu-central-1"
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    get_secret_value_response = client.get_secret_value(SecretId=secret_name)

    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
        secret_obj = json.loads(secret)

    return secret_obj[secret_name]


    