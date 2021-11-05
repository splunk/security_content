import boto3
from botocore.config import Config
import time
import os
import json


def create_key_pair(region):
    my_config = Config(region_name = region)
    epoch_time = str(int(time.time()))
    ssh_key_name = 'key-dt-' + epoch_time
    ec2 = boto3.client('ec2', config=my_config)
    response = ec2.create_key_pair(KeyName=ssh_key_name)
    with open(ssh_key_name, "w") as ssh_key:
        ssh_key.write(response['KeyMaterial'])
    os.chmod(ssh_key_name, 0o600)
    private_key_path = str(os.getcwd() + "/" + ssh_key_name)

    return ssh_key_name, response['KeyMaterial']


def delete_key_pair(region, key_pair_name):
    my_config = Config(region_name = region)
    ec2 = boto3.client('ec2', config=my_config)
    response = ec2.delete_key_pair(KeyName=key_pair_name)


def create_entry_database(region, db_name, name, state, ssh_key_name, private_key):
    resource = boto3.resource('dynamodb', region_name=region)
    table = resource.Table(db_name)
    response = table.put_item(Item= {
        'name': name, 
        'ssh_key_name': ssh_key_name, 
        'private_key': private_key, 
        'status': state
    })


def update_entry_database(region, db_name, name, password, state):
    resource = boto3.resource('dynamodb', region_name=region)
    table = resource.Table(db_name)
    response = table.update_item(
        Key={
            'name': name
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


def delete_entry_database(region, db_name, name):
    resource = boto3.resource('dynamodb', region_name=region)
    table = resource.Table(db_name)
    response = table.delete_item(
        Key={
            'name': name
        }
    )


def get_entry_database(region, db_name, name):
    resource = boto3.resource('dynamodb', region_name=region)
    table = resource.Table(db_name)
    response = table.get_item(
        Key={
            'name': name
        }
    )
    if 'Item' in response:
        return response['Item']
    else:
        return {}


def create_db_database(name, region):
    my_config = Config(region_name = region)
    client = boto3.client('dynamodb', config=my_config)
    response = client.create_table(
        TableName=name,
        KeySchema=[
            {
                'AttributeName': 'name',
                'KeyType': 'HASH'  # Partition key
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'name',
                'AttributeType': 'S'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 10,
            'WriteCapacityUnits': 10
        }
    )    


def delete_db_database(db_name, region):
    dynamodb = boto3.resource('dynamodb', region_name=region)
    table = dynamodb.Table(db_name)
    table.delete()


def create_tf_state_store(name, region):
    my_config = Config(region_name = region)
    s3 = boto3.client('s3', config=my_config)
    response = s3.create_bucket(Bucket=name, CreateBucketConfiguration={'LocationConstraint': region})

    client = boto3.client('dynamodb', config=my_config)
    response = client.create_table(
        TableName=name,
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
    

def delete_tf_state_store(region, name):
    s3 = boto3.resource('s3', region_name=region)
    bucket = s3.Bucket(name)
    bucket.objects.all().delete()
    bucket.delete()

    dynamodb = boto3.resource('dynamodb', region_name=region)
    table = dynamodb.Table(name)
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


    