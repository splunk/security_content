#!/bin/bash
# simple script to run an appinspect API check
EXPECTED_ARGS=2
E_BADARGS=65

if [ $# -lt 2 ]
then
echo "Usage: `basename $0` <token> <app_path>"
echo "Example `basename $0` xxxxXXXXxxxx ~/"
  exit $E_BADARGS
fi

if [ $# -gt $EXPECTED_ARGS ]
then
echo "Too many arguments"
        exit $E_BADARGS
fi

APPINSPECT_TOKEN=$1
APP_PATH=$2

cd $APP_PATH
mkdir report
# submit a inspection job EXPECTS app on same directory
REQUEST_ID=$(curl -s --location --request POST 'https://appinspect.splunk.com/v1/app/validate' --header "Authorization: bearer $APPINSPECT_TOKEN" --form 'app_package=@"DA-ESS-ContentUpdate-latest.tar.gz"' | jq -r '.request_id')
echo "app inspect request: $REQUEST_ID"
sleep 5
STATUS=$(curl -s --location --request GET https://appinspect.splunk.com/v1/app/validate/status/$REQUEST_ID --header "Authorization: bearer $APPINSPECT_TOKEN" | jq -r '.status')
while :
do
	STATUS=$(curl -s --location --request GET https://appinspect.splunk.com/v1/app/validate/status/$REQUEST_ID --header "Authorization: bearer $APPINSPECT_TOKEN" | jq -r '.status')
    if [ $STATUS == "PROCESSING" ] || [ $STATUS == "PREPARING" ]
    then
    	echo "appinspect PROCESSING request: $REQUEST_ID"
    elif [ $STATUS == "SUCCESS" ]
	# REPORT FINISHED CHECK RESULTS
    then
    	echo "appinspect completed inspection"
        curl -s --location --request GET https://appinspect.splunk.com/v1/app/report/$REQUEST_ID --header "Authorization: bearer $APPINSPECT_TOKEN" --header 'Content-Type: text/html' -o report/appinspect_report.html
        FAILS=$(curl -s --location --request GET https://appinspect.splunk.com/v1/app/report/$REQUEST_ID --header "Authorization: bearer $APPINSPECT_TOKEN" --header 'Content-Type: application/json' | jq -r '.summary | .failure')
        ERRORS=$(curl -s --location --request GET https://appinspect.splunk.com/v1/app/report/$REQUEST_ID --header "Authorization: bearer $APPINSPECT_TOKEN" --header 'Content-Type: application/json' | jq -r '.summary | .error')
        if [ $FAILS -gt 1 -o $ERRORS -gt 1 ]
        then
    		echo "ERROR appinspect had $FAILS failures and or $ERRORS errors, see summary report under job artifacts for details"
    		exit 1
    	else
    		echo "appinspect passed successfully, see summary report under job artifacts for details"
        	exit 0
        fi
    else
    	echo "there was an error with app inspect report please see below:"
    	curl -s --location --request GET https://appinspect.splunk.com/v1/app/report/$REQUEST_ID --header "Authorization: bearer $APPINSPECT_TOKEN" --header 'Content-Type: application/json' | jq -r
    	exit 1
	fi
sleep 60
done
exit 0



