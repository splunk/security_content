from os import error
import sys
from time import sleep
import splunklib.client as client
import splunklib.results as results
import requests
import time
import timeit
import datetime
from typing import Union, Tuple

DEFAULT_EVENT_HOST = "ATTACK_DATA_HOST"
DEFAULT_DATA_INDEX = set(["main"])
FAILURE_SLEEP_INTERVAL_SECONDS = 60

def enable_delete_for_admin(splunk_host:str, splunk_port:int, splunk_password:str)->bool:
    try:
        service = client.connect(
            host=splunk_host,
            port=splunk_port,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        raise(Exception("Unable to connect to Splunk instance: " + str(e)))
        

    #write the following contents to /opt/splunk/etc/system/local/authorize.conf
    "[role_admin]"\
    "delete_by_keyword = enabled"\
    "grantableRoles = admin"\
    "importRoles = can_delete;user;power_user"\
    "srchIndexesAllowed = *;_*;main"\
    "srchIndexesDefault = main"\
    "srchMaxTime = 8640000"

    #Run the following search, equivalent to running ./splunk reload auth, to get the settings to take effect
    
    update_changed_auth_search = "| rest splunk_server=* /services/authentication/providers/services/_reload"


    try:
        job = service.jobs.create(update_changed_auth_search)
    except Exception as e:
        error_message = "Unable to enable delete: %s"%(str(e))
        return False
    
    input("Waiting for you to check that delete has been enabled with: %s"%(update_changed_auth_search))
    return True
    '''
    # search and replace \\ with \\\
    # search = search.replace('\\','\\\\')
    role = service.roles['admin']
    try:
        role.grant('delete_by_keyword')
    except Exception as e:
        print("Error - failed trying to grant 'can_delete' privs to admin: [%s]"%(str(e)))
        return False
    '''
    return True




def get_number_of_indexed_events(splunk_host, splunk_port, splunk_password, index:str, event_host:str=DEFAULT_EVENT_HOST, sourcetype:Union[str,None]=None )->int:

    try:
        service = client.connect(
            host=splunk_host,
            port=splunk_port,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        raise(Exception("Unable to connect to Splunk instance: " + str(e)))

    if sourcetype is not None:
        search = f'''search index="{index}" sourcetype="{sourcetype}" host="{event_host}" | stats count'''
    else:
        search = f'''search index="{index}" host="{event_host}" | stats count'''
    kwargs = {"exec_mode":"blocking"}
    try:
        job = service.jobs.create(search, **kwargs)
  
        #This returns the count in string form, not as an int. For example:
        #OrderedDict([('count', '59630')])
        results_stream = job.results(output_mode='json')
        count = None
        for res in results.JSONResultsReader(results_stream):
            if 'count' in res:
                count = int(res['count'],10)
        if count is None:
            raise Exception(f"Expected the get_number_of_indexed_events search to only return 1 count, but got {len(search_results)} instead.")
        
        return count    

    except Exception as e:
        raise Exception("Error trying to get the count while waiting for indexing to complete: %s"%(str(e)))
        
    


def wait_for_indexing_to_complete(splunk_host, splunk_port, splunk_password, sourcetype:str, index:str, check_interval_seconds:int=10)->bool:
    startTime = timeit.default_timer()
    previous_count = -1
    time.sleep(check_interval_seconds)
    while True:
        new_count = get_number_of_indexed_events(splunk_host, splunk_port, splunk_password, index=index, sourcetype=sourcetype)
        #print(f"Previous Count [{previous_count}] New Count [{new_count}]")
        if previous_count == -1:
            previous_count = new_count
        else:
            if new_count == previous_count:
                stopTime = timeit.default_timer()
                return True
            else:
                previous_count = new_count
        
        #If new_count is really low, then the server is taking some extra time to index the data.
        # So sleep for longer to make sure that we give time to complete (or at least process more
        # events so we don't return from this function prematurely) 
        if new_count < 2:
            time.sleep(check_interval_seconds*3)
        else:
            time.sleep(check_interval_seconds)
        



def test_detection_search(splunk_host:str, splunk_port:int, splunk_password:str, search:str, pass_condition:str, 
                          detection_name:str, earliest_time:str, latest_time:str, attempts_remaining:int=4, 
                          failure_sleep_interval_seconds:int=FAILURE_SLEEP_INTERVAL_SECONDS, FORCE_ALL_TIME=True)->dict:
    #Since this is an attempt, decrement the number of remaining attempts
    attempts_remaining -= 1
    
    #remove leading and trailing whitespace from the detection.
    #If we don't do this with leading whitespace, this can cause
    #an issue with the logic below - mainly prepending "|" in front
    # of searches that look like " | tstats <something>"
    if search != search.strip():
        print(f"The detection contained in {detection_name} contains leading or trailing whitespace.  Please update this search to remove that whitespace.")
        search = search.strip()
    
    if search.startswith('|'):
        updated_search = search
    else:
        updated_search = 'search ' + search 


    #Set the mode and timeframe, if required
    kwargs = {"exec_mode": "blocking"}
    if not FORCE_ALL_TIME:
        kwargs.update({"earliest_time": earliest_time,
                       "latest_time": latest_time})

    #Append the pass condition to the search
    splunk_search = f"{updated_search} {pass_condition}"

    try:
        service = client.connect(
            host=splunk_host,
            port=splunk_port,

            username='admin',
            password=splunk_password
        )
    except Exception as e:
        error_message = "Unable to connect to Splunk instance: %s"%(str(e))
        print(error_message,file=sys.stderr)
        return {"status":False, "message":error_message}


    try:
        job = service.jobs.create(splunk_search, **kwargs)
        results_stream = job.results(output_mode='json')
        #Return all the content returned by the search
        return job.content

    except Exception as e:
        error_message = "Unable to execute detection: %s"%(str(e))
        print(error_message,file=sys.stderr)
        {"status":False, "message":error_message}

    


def delete_attack_data(splunk_host:str, splunk_password:str, splunk_port:int, indices:set[str]=[DEFAULT_DATA_INDEX], host:str=DEFAULT_EVENT_HOST)->bool:
    
    
    try:
        service = client.connect(
            host=splunk_host,
            port=splunk_port,

            username='admin',
            password=splunk_password
        )
    except Exception as e:

        raise(Exception("Unable to connect to Splunk instance: " + str(e)))


    #print(f"Deleting data for {detection_filename}: {indices}")
    for index in indices:
        while (get_number_of_indexed_events(splunk_host, splunk_port, splunk_password, index=index, event_host=host) != 0) :
            splunk_search = f'search index="{index}" host="{host}" | delete'
            kwargs = {
                    "exec_mode": "blocking",
                    "dispatch.earliest_time": "-1d",
                    "dispatch.latest_time": "now"}
            try:
                
                job = service.jobs.create(splunk_search, **kwargs)
                results_stream = job.results(output_mode='json')
                reader = results.JSONResultsReader(results_stream)


            except Exception as e:
                raise(Exception(f"Trouble deleting data using the search {splunk_search}: {str(e)}"))
        
    
    return True
