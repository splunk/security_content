from os import error
import sys
from time import sleep
import splunklib.client as client
import splunklib.results as results
import requests
import time
import timeit
import datetime
from typing import Union

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




def get_number_of_indexed_events(splunk_host, splunk_port, splunk_password, index:str, sourcetype:Union[str,None]=None )->int:

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
        search = '''search index="%s" sourcetype="%s" | stats count'''%(index,sourcetype)
    else:
        search = '''search index="%s" | stats count'''%(index)
    kwargs = {"exec_mode":"blocking"}
    try:
        search_result = service.jobs.create(search, **kwargs)
  
        #This returns the count in string form, not as an int. For example:
        #OrderedDict([('count', '59630')])
        search_results = list(results.ResultsReader(search_result.results()))
        if len(search_results) != 1:
            raise Exception(f"Expected the get_number_of_indexed_events search to only return 1 count, but got {len(search_results)} instead.")
        
        count = int(search_results[0]['count'])
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
        

'''
def wait_for_indexing_to_complete(splunk_host, splunk_port, splunk_password, sourcetype:str, index:str, check_interval_seconds:int=10):
    
    startTime = timeit.default_timer()
    previous_count = -1
    time.sleep(check_interval_seconds/2)
    while True:
        #print("waiting for search...")
        try:
            service = client.connect(
                host=splunk_host,
                port=splunk_port,
                username='admin',
                password=splunk_password
            )
        except Exception as e:
            raise(Exception("Unable to connect to Splunk instance: " + str(e)))

        search = 'search index="%s" sourcetype="%s" | stats count'%(index,sourcetype)
        kwargs = {"exec_mode":"blocking"}
        try:
            search_result = service.jobs.create(search, **kwargs)
        except Exception as e:
            print("Error while waiting for indexing of data to complete: %s"%(str(e)))
            #return False
        
        #This returns the count in string form, not as an int. For example:
        #OrderedDict([('count', '59630')])
        try:
            for result in results.ResultsReader(search_result.results()):
                count = int(result['count'])
                print("count is %d, previous count is %d"%(count,previous_count))
                if previous_count == -1:
                    if count == 0:
                        pass
                    else:
                        previous_count = count
                else:
                    if count == previous_count:
                        #After waiting for the check interval, we return the same number of results.  The indexing must be complete 
                        stopTime = timeit.default_timer()
                        #print("Indexing completed after: %s "%(datetime.timedelta(seconds=stopTime-startTime)))
                        return True
                    else:
                        previous_count = count
    
        except Exception as e:
            print("Error trying to get the count while waiting for indexing to complete: %s"%(str(e)))
            #return False
        time.sleep(check_interval_seconds)
'''


def test_baseline_search(splunk_host, splunk_port, splunk_password, search, pass_condition, baseline_name, baseline_file, earliest_time, latest_time)->dict:
    try:
        service = client.connect(
            host=splunk_host,
            port=splunk_port,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        raise(Exception("Unable to connect to Splunk instance: " + str(e)))
        


    # search and replace \\ with \\\
    # search = search.replace('\\','\\\\')

    if search.startswith('|'):
        search = search
    else:
        search = 'search ' + search

    kwargs = {"exec_mode": "blocking",
              "dispatch.earliest_time": earliest_time,
              "dispatch.latest_time": latest_time}

    splunk_search = search + ' ' + pass_condition

    try:
        job = service.jobs.create(splunk_search, **kwargs)
    except Exception as e:
        raise(Exception("Unable to execute baseline: " + str(e)))
        

    test_results = dict()
    test_results['diskUsage'] = job['diskUsage']
    test_results['runDuration'] = job['runDuration']
    test_results['baseline_name'] = baseline_name
    test_results['baseline_file'] = baseline_file
    test_results['scanCount'] = job['scanCount']

    if int(job['resultCount']) != 1:
        print("Test failed for baseline: " + baseline_name)
        test_results['error'] = True
        return test_results
    else:
        print("Test successful for baseline: " + baseline_name)
        test_results['error'] = False
        return test_results



def test_detection_search(splunk_host:str, splunk_port:int, splunk_password:str, search:str, pass_condition:str, detection_name:str, detection_file:str, earliest_time:str, latest_time:str)->dict:
    if search.startswith('|'):
        search = search
    else:
        search = 'search ' + search 

    kwargs = {"exec_mode": "blocking",
              "dispatch.earliest_time": "-1d",
              "dispatch.latest_time": "now"}

    splunk_search = search + ' ' + pass_condition
    test_results = dict()
    
    #These will always be present. By default, we will say that the
    #test has failed AND there was an error (until they are set otherwise)
    test_results['search_string'] = splunk_search
    test_results['detection_name'] = detection_name
    test_results['detection_file'] = detection_file
    
    test_results['success'] = False
    test_results['error'] = True

    
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
        test_results['error'] = True
        test_results['detection_error'] = error_message
        return test_results


    # search and replace \\ with \\\
    # search = search.replace('\\','\\\\')

   

    #print("SEARCH: %s"%(splunk_search))


    try:
        job = service.jobs.create(splunk_search, **kwargs)
    except Exception as e:
        
        error_message = "Unable to execute detection: %s"%(str(e))
        print(error_message,file=sys.stderr)
        test_results['error'] = True
        test_results['detection_error'] = error_message
        return test_results

    test_results['diskUsage'] = job['diskUsage']
    test_results['runDuration'] = job['runDuration']
    test_results['scanCount'] = job['scanCount']
    
    #If we get this far, then there was not an error
    #The search may have FAILED, but there was no error in the search
    test_results['error'] = False 


    #Should this be 1 for a pass, or should it be greater than 0?
    if int(job['resultCount']) != 1:
        #print("Test failed for detection: " + detection_name)
        test_results['success'] = False
        return test_results
    else:
        #print("Test successful for detection: " + detection_name)
        test_results['success'] = True
        return test_results


def delete_attack_data(splunk_host:str, splunk_password:str, splunk_port:int, wait_on_delete:Union[dict,None], search_string:str, detection_filename:str, index:str="main")->bool:
    
    try:
        service = client.connect(
            host=splunk_host,
            port=splunk_port,

            username='admin',
            password=splunk_password
        )
    except Exception as e:

        raise(Exception("Unable to connect to Splunk instance: " + str(e)))

    #splunk_search = 'search index=test* | delete'
    if wait_on_delete:
        print(wait_on_delete['message'])
        print("FILENAME : [%s]"%(detection_filename))
        print("SEARCH   :\n%s"%(search_string))
        _ = input("****************Press ENTER to Complete Test and DELETE data****************\n\n\n")
    
    data_exists = True



    while (get_number_of_indexed_events(splunk_host, splunk_port, splunk_password, index=index) != 0) :
        splunk_search = f'search index={index} | delete'

        kwargs = {
                "exec_mode": "blocking",
                "dispatch.earliest_time": "-1d",
                "dispatch.latest_time": "now"}
        try:
            
            job = service.jobs.create(splunk_search, **kwargs)
            reader = results.ResultsReader(job)

            
            '''
            error_in_results = False
            for result in reader:
                if hasattr(result,"message") and hasattr(result,"type") and ("You have insufficient privileges to delete events" in result.message or result.type == "FATAL"):
                    print("Delete is not enabled for admin: [%s] - enabling delete and trying to delete again..."%(result.message), file=sys.stderr)
                    if already_enabled_delete is True:
                        print("We already enabled delete, but the setting did not take effect.")
                        raise(Exception("Enabling delete command failed to take effect"))
                    if enable_delete_for_admin(splunk_host, splunk_port,splunk_password) != True:
                        raise(Exception("Failure enabling delete for admin. We cannot continue"))
                    # We enabled delete, so now we will try to delete again
                    already_enabled_delete = True
                    break
                else:
                    #This is not one of the error messages, do nothing
                    pass
            '''
            #No need to issue Delete command again, we will now break out of the loop
            #if error_in_results is False:
            #    data_exists = False

            #Otherwise, we will loop again

        except Exception as e:
            print(f"Trouble deleting data from a run.... we will try again: {str(e)}")
            time.sleep(5)
            #raise(Exception("Unable to delete data from a run: " + str(e)))
        
    
    return True
