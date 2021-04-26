# SSA Testing 
The SSA testing job will test SSA detections with the staging tenant research. It will execute the following steps to test SSA detections:
* Create a temporary index for results
* Create a temporary pipeline and decorate it
* Activate a temporary pipeline
* Send raw data to the testing tenant
* Collect the results from the temporary index
* Tear down the test

# SSA Testing GitLab CI
SSA testing job is configured as a GitLAB CI job, which will test all changed and newly created SSA detections in the given branch compared to the develop branch. For example, if you create two new SSA detections with its corrsponding test files, it will test these two SSA detections in the GitLab CI job. It can take up to 30 min until the GitLab CI job will start.
The GitLab CI job is limited to branches with the prefix ssa*, therefore you need to name your branch ssa* in order to make the GitLab CI job work. 

# SSA Testing Manual
Additional to the GitLab CI testing, you can do ad-hoc testing during SSA detection development. First you need, to prepare your virtualenv:
````
cd bin/ssa-end-to-end-testing
virtualenv -p python3 venv && source venv/bin/activate && pip3 install -r requirements.txt
````
Then you can run the SSA detection test (please consider that your detections needs to be pushed to the GitHub repository):
````
python run_ssa_smoketest.py -e staging -s research -b [your_branch] -t [your_token]
````
The token can be derived from the SSA tenant.  
In order to only test a single detection, you can run the following command:
````
python run_ssa_smoketest.py -e staging -s research -b [your_branch] -tf endpoint/ssa___detect_pass_hash.test.yml -t [your_token]
````