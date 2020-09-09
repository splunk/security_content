# Automated Detection Testing
Testing detection is a very important task during detection engineering. As it takes a lot of time and is a repeating task, we used the Attack Range to build an automated detection testing service.

## Architecture
![Architecture](automated_detection_testing/architecture_automated_detection_testing.png)
The automated detection testing is using AWS Batch as execution engine. AWS batch allows you to run batch computing jobs, in our case a automated detection test. detection_service.py is the executable which controls the detection test. This executable is deployed in a docker container which is used by AWS Batch.


## Usage
```
python detection_service.py
usage: detection_service.py [-h] -tfn TEST_FILE_NAME [-arr ATTACK_RANGE_REPO]
                            [-arb ATTACK_RANGE_BRANCH]
                            [-scr SECURITY_CONTENT_REPO]
                            [-scb SECURITY_CONTENT_BRANCH]
                            [-adr ATTACK_DATA_REPO] [-adb ATTACK_DATA_BRANCH]
                            [-gt GITHUB_TOKEN] [-smk SECRETS_MANAGER_KEY]
detection_service.py: error: the following arguments are required: -tfn/--test_file_name
```

The detection_service.py has one mandatory parameter, which is --test_file_name. This parameter will look into the security content repository under tests for the specified test file (without extension). The other parameters are optional and can be used to specify forks of projects or specific branches. The detection_service.py is creating Pull Requests after a successful test. Therefore, it needs a Github OAUTH Token. This can be either added with the parameter --github_token or can be derived from the [AWS secrets manager](https://aws.amazon.com/secrets-manager/) through --secrets_manager_key. Let's have a look how to use the detection service after you deployed it:

Example 1:
```
aws batch submit-job --job-name detection_test_T1003_001 --job-definition detection_service_job --job-queue detection_service_queue --container-overrides '{"command": ["-tfn", "T1003_001"]}'
```

Example 2:
```
aws batch submit-job --job-name detection_test_T1003_001 --job-definition detection_service_job --job-queue detection_service_queue --container-overrides '{"command": ["-tfn", "T1003_001", "-scr", "P4T12ICK/security-content", "-scb", "develop_detection_T1003", "-smk", "github_token"]}'
```

## Deployment
- Configure AWS Batch based on the following tutorial https://stackify.com/aws-batch-guide/ and the docker file.
