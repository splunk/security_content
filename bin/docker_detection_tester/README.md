# Batch Detection Testing

The Splunk Threat Research Team produces the [Enterprise Security Content Update Splunk App](https://splunkbase.splunk.com/app/3449/), a power app that includes hundreds of curated, tested detections that you can run on your own Splunk Enterprise Server today.  The splunk/security_content repo gives users an insight into our work and allows them to replicate our workflow and even author their own detections!

A core component of ESCU is that all of detections must be tested and validated against datasets to ensure they work correctly.  In order to achieve that, the Security Content Detection Testing System was built with a few goals in mind:
 - How can we quickly test a small number of detections, and how can I easily debug those detections?
 - How can we reliably test new or modified detections every time they are committed to our repo (or every time that a PR is created) inside of GitHub Actions?
 - At the time of this writing, ESCU contains over 550 detections!  How can we quickly test a large number of detections?
 - How can we run these tests on a wide variety of architectures, from develops' own machines to GitHub Actions to other Cloud Instances?

This architecture diagram gives insight into the workflow:
In summary, the tool:

 1. Downloads the latest version of the security_content Repo
 2. Lints/Sanity Checks all the Detections
 3. Builds an ESCU Splunk App
 4. Starts Docker containers (available from Docker Hub as splunk/splunk:latest), installing required Splunkbase Apps and ESCU
 5. Distributes Detection Tests Across those Containers
 6. Summarizes the Results of those Detections


# Running a Basic Test

## Running the Tool
The easiest way to run a tests with default, which is suitable for most use cases, is to run:

    python detection_testing_exectuion.py run --branch BRANCH_TO_TEST [--splunkbase_username YOUR_USERNAME --splunkbase_password YOUR_PASSWORD]
    
 While the test is running, you'll see helpful information printed, letting you know what step of the process is taking place and what detection is being tested.
 When you start your Splunk Server, the credentials will be printed out on the command line.  You may want to use these credentials to log into the Splunk server, hosted locally, during testing for debugging or other exploration:

    ***********************
    Log into your [1] Splunk Container(s) after they boot at http://127.0.0.1:[8000-8000]
    Splunk App Username: [admin]
    Splunk App Password: [PBlZEeGvQrOF57zmUXFPOP]
    ***********************

While you're running, you'll receive helpful progress updates each minute.  They give you information about how long your test has been running, your approximate time remaining, and your approximate system load.  Please note that this is total system load, not JUST load used by the detection testing:

    ***********PROGRESS UPDATE***********
    Elapsed Time               : 0:27:53.358628
    Estimated Remaining Time   : 0:49:18.896474
    Tests to run               : 36
    Tests currently running    : 1
    Tests completed            : 20
        Success : 15
        Failure : 5
        Error   : 0
    System Information:
        Total CPU Usage   : 44% (2 CPUs)
        Total Memory Usage: 2.1GB USED / 6.8GB TOTAL
        Total Disk Usage  : 21.4GB USED / 83.2GB TOTAL

 Since you're probably running locally to test and debug your searches, there is a feature (enabled by default) called interactive_failure.  If one of your detections fails, the test will pause and the offending detection will print out a message like this:



 This allows you to login to your Splunk server and debug the search.  All of the uploaded data for this search remains on the server.  To continue, delete the data for this search, and move on to the next search, simply hit "Enter" in the command prompt. 
 
When the test run is completed, you'll see some cleanup and summarization information.  Finally, asimple output summarizes the test run, such as:

    All containers completed testing!
    Removing all attack data that was downloaded during this test at: [/home/runner/work/security_content/security_content/bin/automated_detection_testing/ci/detection_testing_batch/attack_data_ogcm5da9]
    Successfully removed all attack data
    Generating test_results/success.csv...Done with [48] detections
    Generating test_results/failure.csv...Done with [9] detections
    Generating test_results/error.csv...Done with [0] detections
    Generating test_results/combined.csv...Done with [57] detections
    Settings updated.  Writing results to: test_results/detection_failure_manifest.json
    Summary:
        Total Tests: 57
        Total Pass : 48
        Total Fail : 9 (0 of these were ERRORS)
    Test Execution Successful

 Note that execution of this test will be successful if all tests complete, **even if 1 or more of the tests fail or contain errors!**

## Viewing Detailed Results
A number of helpful files are generated when the tool runs and written to the `test_results/` directory.  The most important files are:

 - summary.json - A file which contains a summary of the test :
		 - Successes, failures, and errors 
		 - The Splunk Apps (and their versions) that were installed 
		 - Specific Information about the Branch and Commit Hash the test was run against 
		 - Detailed Information about each individual test, including success/failure/error information.
		 
 - detection_failure_manifest.json - A file which allows you to replicate your test, testing ONLY the detections that have failed.  This gives the user the chance to interactively debug these failures.  This is especially useful because it is also generated by the GitHub Actions CI Pipeline - allowing you to pull a single file and debug failed tests locally in minutes!  Because it contains specific application versions and the commit hash, this also lets you reproduce this test, exactly, at any point in the future.


## Advanced Usage

### Command Line Arguments
There are a large number of configurable parameters for advanced users.  To view the most common parameters, simply run

    python detection_testing_batch.py --help

These commands will be described in more detail at a later time.