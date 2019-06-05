
# encoding = utf-8

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="escu-contextualize")
    helper.addevent("world", sourcetype="escu-contextualize")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.log_info("Alert action escu_contextualize started.")
    import splunk.rest
    import json
    import time

    # TODO: Implement your alert action logic here
    runSearch = "/servicesNS/nobody/DA-ESS-ContentUpdate/search/jobs?output_mode=json&count=-1"
    pollSearch = "/servicesNS/nobody/DA-ESS-ContentUpdate/search/jobs/"
    #Create an empty dict to hold POST args/user input
    pdata = {}

    # TODO: Implement your alert action logic here
    try:
        events = helper.get_events()
        for event in events:
            helper.log_info("Starting checking event")

            #internalSearch = search_list.searches['search1']
            #quick check to determine if the key 'dest' exists
            #in the event. We will use this later on
            #as we import a search and push that info into
            #the search string
            if 'search_name' not in event:
                helper.log_info("No search_name in event")
                continue
            #based on the existence of a 'dest' key in the event
            #we can then pass this into a set of search strings
            #in this case it's in the search_list.py file
            #that lives in the ../bin/ta_search_response directory

            # Endpoint searches have user field, but some contextual searches need src_user
            if 'user' in event and 'src_user' not in event:
                event['src_user'] = event['user']

            helper.log_info("Gathering contextual search data")
            get_contextual_search_data = "| rest /services/saved/searches splunk_server=local count=0 | search * [| rest /services/configs/conf-analytic_stories splunk_server=local count=0 | search detection_searches=\"*" + event['search_name'][:-7] + "*\" | spath input=contextual_searches path={} output=cs | mvexpand cs | table cs | sort cs | uniq cs | rename cs as title] | table title search, action.escu.earliest_time_offset, action.escu.latest_time_offset, action.escu.fields_required"
            #add this to our post data for the splunk search
            pdata = {'search': get_contextual_search_data}
            #make the search request to the Splunk REST endpoint
            head, content = splunk.rest.simpleRequest(runSearch, sessionKey=helper.settings["session_key"], postargs=pdata, method='POST')
            #get our search ID/sid
            data = json.loads(content)

            isDone = False
            #poll the search endpoint until the search is done
            while not isDone:
                head, content = splunk.rest.simpleRequest(pollSearch + data['sid'] + "?output_mode=json", sessionKey=helper.settings["session_key"], method='GET')
                status = json.loads(content)
                if status['entry'][0]['content']['isDone']:
                    isDone = True

            head, content = splunk.rest.simpleRequest(pollSearch + data['sid'] + "/results?output_mode=json", sessionKey=helper.settings["session_key"], method='GET')

            #load the search results (json array)
            searches_to_run = {}
            earlier_offset = {}
            later_offset = {}
            fields_required = {}
            contextual_search_data = json.loads(content)
            for cs_data in contextual_search_data['results']:
                cs = cs_data['title']

                searches_to_run[cs] = cs_data['search']
                earlier_offset[cs] = int(cs_data['action.escu.earliest_time_offset'])
                later_offset[cs] = int(cs_data['action.escu.latest_time_offset'])
                fields_required[cs] = cs_data['action.escu.fields_required']

            helper.log_info("Gathering Context")
            for search_name, search in searches_to_run.iteritems():

                # If we don't have data for that search, skip it
                have_needed_data = True
                for field in json.loads(fields_required[search_name]):
                    if field not in event:
                        have_needed_data = False
                        helper.log_info("No " + field + " in data, skipped " + search_name)
                        break

                if not have_needed_data:
                    continue

                formatted_search = search.format(**event)
                cs_sdata = {
                    'search': formatted_search,
                    'earliest_time' : int(event["_time"]) - earlier_offset[search_name],
                    'latest_time' : int(event["_time"]) + later_offset[search_name]
                }
                helper.log_info(search_name)
                head, content = splunk.rest.simpleRequest(runSearch, sessionKey=helper.settings["session_key"], postargs=cs_sdata, method='POST')
                #get our search ID/sid
                sid_data = json.loads(content)

                isDone = False
                #poll the search endpoint until the search is done
                time_limit = 120
                current_time = 0
                while not isDone:
                    head, content = splunk.rest.simpleRequest(pollSearch + sid_data['sid'] + "?output_mode=json", sessionKey=helper.settings["session_key"], method='GET')
                    status = json.loads(content)
                    if status['entry'][0]['content']['isDone']:
                        isDone = True
                    else:
                        time.sleep(1)

                    current_time += 1
                    if current_time > time_limit:
                        break

                if isDone:
                    head, contextual_content = splunk.rest.simpleRequest(pollSearch + sid_data['sid'] + "/results?output_mode=json", sessionKey=helper.settings["session_key"], method='GET')
                    contextual_data = json.loads(contextual_content)
                    for new_data in  contextual_data['results']:
                        new_data['search_name'] = search_name
                        results = json.dumps(new_data)
                        helper.addevent(str(results), sourcetype="escu-contextualize")
                else:
                    new_data = {}
                    new_data['search_name'] = search_name
                    new_data['msg'] = 'Search time limit of %d seconds reached' % time_limit
                    results = json.dumps(new_data)
                    helper.addevent(str(results), sourcetype="escu-contextualize")
            helper.writeevents(index="main", host="localhost", source="localhost")

        return 0

    except Exception as e:
        helper.log_error("Failure {}".format(str(e)))
        return 1
