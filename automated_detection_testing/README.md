# Automated Detection Testing
Testing detection is a very important task during detection engineering. As it takes a lot of time and is a repeating task, we used the Attack Range to build an automated detection testing service.

## Architecture
![Architecture](automated_detection_testing/architecture_automated_detection_testing.png)
The automated detection testing is using AWS Batch as execution engine. AWS batch allows you to run batch computing jobs, in our case a automated detection test. detection_service.py is the executable which controls the detection test. This executable is deployed in a docker container which is used by AWS Batch.


## Usage
```
python detection_service.py
usage: detection_service.py [-h] -tfn TEST_FILE_NAME
                            [-arr ATTACK_RANGE_REPO]
                            [-arb ATTACK_RANGE_BRANCH]
                            [-scr SECURITY_CONTENT_REPO]
                            [-scb SECURITY_CONTENT_BRANCH]
                            [-gt GITHUB_TOKEN]
                            [-smk SECRETS_MANAGER_KEY]
                            [-s3b S3_BUCKET]
detection_service.py: error: the following arguments are required: -tfn/--test_file_name
```

The detection_service.py has one mandatory parameter, which is --test_file_name. This parameter will look into the security content repository under tests for the specified test file (without extension). The other parameters are optional and can be used to specify forks of projects or specific branches. The detection_service.py is creating Pull Requests after a successful test. Therefore, it needs a Github OAUTH Token. This can be either added with the parameter --github_token or can be derived from the [AWS secrets manager](https://aws.amazon.com/secrets-manager/) through --secrets_manager_key. Let's have a look how to use the detection service after you deployed it.

Let's have a look how to use the attack data service after you deployed it:

### Using AWS CLI

Example 1:
```
aws batch submit-job --job-name detection_test_T1003_001 --job-definition detection_service_job --job-queue detection_service_queue --container-overrides '{"command": ["-tfn", "T1003_001"]}'
```

Example 2:
```
aws batch submit-job --job-name detection_test_T1003_001 --job-definition detection_service_job --job-queue detection_service_queue --container-overrides '{"command": ["-tfn", "T1003_001", "-scr", "P4T12ICK/security-content", "-scb", "develop_detection_T1003", "-smk", "github_token"], "-s3b", "my_detection_test_bucket"}'
```

### Using AWS Web Portal
The Attack Data Generation Service can be also triggered over the AWS Web Portal. You will first click on the service "Batch" and then click on the left side "Jobs". Then, you click on "submit new job". You will fill the variables according to the following screenshot and click on "Submit".
![AWS Batch Job](attack_data_service/static/aws_batch_submit_job.png)


## Deployment
In order to deploy the Detection Testing Service to AWS Batch, please follow this guideline. This description assumes that you will deploy the Detection Testing Service to the region eu-central-1.

### Prerequisites
- AWS account
- IAM user with administrative permissions
- AWS CLI
- Docker
- S3 bucket to store detection test data

### Create GitHub Token
The GitHub Token allows the Automate Detection Testing Service to create Pull Requests.
- Create a Personal GitHub Acces Token according to the following [tutorial](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/creating-a-personal-access-token)

### Upload GitHub Token to AWS Secrets Manager
- Connect to AWS Web Portal
- Go to the AWS Secrets Manager
- Choose region eu-central-1
- Click on "Store a new secret"
- Click on "Other type of secrets"
- Add "github_token" as key
- Copy the github token as value
- Click on "Next"
- Use "github_token" as Secret name
- Click on "Next"
- Click on "Next"
- Click on "Store"

### Create AWS ECR Repository
- Connect to AWS Web Portal
- Go to service "Elastic Container Registry"
- Click on "Repositories" under Amazon ECR on the left side.
- Click on "Create repository"
- Add "awsbatch/detection-testing-service" as repository name
- Click on "Create repository"

### Build and Upload Docker File
- Navgigate to the automated_detection_testing folder:
```
cd automated_detection_testing
```
- Build the docker container
```
docker build --tag awsbatch/detection-testing-service .
```
- Tag the docker container (The aws account number can be found in the AWS ECR Repository path)
```
docker tag awsbatch/detection-testing-service:latest [aws_account_number].dkr.ecr.eu-central-1.amazonaws.com/awsbatch/detection-testing-service:latest
```
- Login to AWS ECR
```
aws ecr get-login-password --region eu-central-1 | docker login --username AWS --password-stdin [aws_account_number].dkr.ecr.eu-central-1.amazonaws.com
```
- Upload Docker container
```
docker push [aws_account_number].dkr.ecr.eu-central-1.amazonaws.com/awsbatch/detection-testing-service:latest
```

### Configure AWS Batch
- Connect to AWS Web Portal
- Go to service "AWS Batch"
- Click on "Compute environments" on the left side
- Click on "Create"
- Use "detection_testing_service_environment" as "Compute environment name"
- Define Instance Configuration according to your demand. You can choose small instance types, because the instance will run docker and docker will only run a python script.
- Define the vpc and subnets which you want to use in Networking
- Click on "create compute environment"

- Click on "Job queues" on the left side
- Click on "Create"
- Use "detection_testing_service_queue" as "Job queue name"
- Select "detection_testing_service_environment" as "compute environment"
- Click on "Create"

- Go to service "IAM"
- Create the following role with name: detection_testing_service_role with the Policies AmazonEC2FullAccess, SecretsManagerReadWrite and AmazonS3FullAccess

- Go to service "AWS Batch"
- Click on "Job definitions" on the left side
- Click on "Create"
- Use "detection_testing_service" as Name
- Use 3000 as "Execution timeout"
- Container properties:
- Use "[aws_account_number].dkr.ecr.eu-central-1.amazonaws.com/awsbatch/detection-testing-service:latest" as Image
- remove Command from Command field
- Use 2 in vCPUs
- Use 2048 in Memory
- Click on "Additional configuration"
- Use "detection_testing_service_role" as Job Role
- Use root as "User" under Security
- Click on "Create"

## Local Detection Testing
The Detection Testing Service can be also run locally.
- Navgigate to the automated_detection_testing folder:
```
cd automated_detection_testing
```
- Build the docker container
```
docker build --tag awsbatch/detection-testing-service .
```
- Run the docker container
```
docker run -v ~/.aws/credentials:/root/.aws/credentials:ro --name attackrange awsbatch/detection-testing-service:latest -tfn T1003_001 -s3b my_detection_test_bucket -scr P4T12ICK/security-content -scb new_detections
```

## Troubleshooting
AWS Batch will store the logs in Cloudwatch. Check the cloudwatch logs for Troubleshooting.
