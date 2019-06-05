# Copyright (C) 2009-2016 Splunk Inc. All Rights Reserved.
#
# This file contains all possible options for a usecases.conf file.  Use this file to define a use-case.
#
# To learn more about configuration files (including precedence) please see the documentation
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#
[<analytic_story_name>]
category = [string]
    * The category of the analytic story
    * Defaults to None

creation_time = [datetime]
    * The date & time that the analytic story was first created
    * The date-time should be formatted an epoch time (in GMT)

data_models = [json]
    * A JSON list of the data models used by the analytic story
    * Defaults to None

description = [string]
    * A bried description of the analytic story
    * Defaults to None

id = [string]
    * A description of the analytic story
    * Defaults to None

mappings = [json]
    * A JSON dictionary of the different mappings this story maps to
    * See appendix B for the format of this field
    * Defaults to None

modification_time = [datetime]
    * The date & time that the analytic story was last modified
    * The date-time should be formatted an epoch time (in GMT)

narrative = [string]
    * A longer narrative of the analytic story that describes the detection searches, any support searches,
    * and the corresponding contextual and investigative searches
    * Defaults to None

references = [json]
    * A JSON list of references for this story
    * Defaults to None

detection_searches = [json]
    * A JSON list of the detection searches that the analytic story applies to.
    * See appendix A for the format of this field
    * Defaults to None

investigative_searches = [json]
    * A JSON list of the investigative searches that the analytic story applies to.
    * See appendix A for the format of this field
    * Defaults to None

contextual_searches = [json]
    * A JSON list of contextual searches that the analytic story applies to.
    * See appendix A for the format of this field
    * Defaults to None

support_searches = [json]
    * JSON list of support searches that the analytic story applies to.
    * See appendix A for the format of this field
    * Defaults to None

providing_technologies = [json]
    * A JSON list of example technologies that can be used to capture the data needed for the analytic story
    * Defaults to None

version = [int]
    * An integer indicating which revision of the analytic story this is
    * This value should start with one and increase for each release

###### Appendix A: *_searches Specification #######
# This can just be a list of saved search names. However, this also supports a hierarchical structure to denote searches that rely on other searches.
#
# A non-hierarchical version would look like this:
#      [ "search1", "search2" ]
#
# A hierarchical version would look like this:
#[
#       "search1": [ "search1a", "search1b" ],
#       "search2": [ "search2a" ]
#]


###### Appendix B: Mappings Specification #######
#
# This is a dictionary of the different mappings this analytic story maps to.
# The mapping will be the key, and the value will be an array of the labels it applies to
#
# Example:
# {
#   "kill_chain_phase": ["Delivery", "Command and Control"],
#   "sans cis": ["CIS 9", "CIS 12"],
#   "att&ck": ["Command and Control"]
# }
#

