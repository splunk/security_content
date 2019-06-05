# Copyright (C) 2009-2016 Splunk Inc. All Rights Reserved.
#
# This file contains additional options for an alert_actions.conf file.
#
# To learn more about configuration files (including precedence) please see the documentation
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#
[escu]

enabled = [true|false|0|1]
    * Whether or not this use-case is enabled.
    * This exists so that we are a true noop for scheduled searches.
    * action.usecase=0 action.usecase.enabled=1
    * Required.
    * Defaults to false.

version = [string]
    * Version of this search

asset_at_risk = [string]
    * The type of asset that is at risk from the behavior this search is attempting to find
    * Defaults to None

category = [string]
    * A description of the category that this use-case falls into
    * Defaults to None

channel = [string]
    * The name of the channel the search belongs to

confidence = [low|medium|high]
    * A description of the confidence value
    * Valid values are: low, medium, high
    * Defaults to None

creation_time = [datetime]
    * The date & time that the search was first created
    * The date-time should be formatted an epoch time (in GMT)

datamodels = [json]
    * A JSON list of the data models used by this search
    * Defaults to None

eli5 = [string]
    * Text explaining this search to a 5 year old
    * Defaults to None

full_search_name = [string]
    * The entire search name
    * Defaults to None

how_to_implement = [string]
    * Text discussing what needs to be done to implement this search and any local modifications that can be performed
    * Defaults to None

known_false_positives = [string]
    * A description of cases in which this use-case may generate false positive alerts
    * Defaults to None

mappings = [json]
    * A JSON list of the kill chain phases this search covers
    * Defaults to None

modification_time = [datetime]
    * The date that the search was last modified
    * The date-time should be formatted an epoch time (in GMT)

remediation = [string]
    * A high-level description of how the issue described by this use-case can be remediated.
    * Defaults to None

providing_technologies = [json]
    * A JSON list of the technology examples that can be used to gather data to power this search
    * Defaults to None

analytic_story = [json]
    * A JSON list of the use cases this search applies to
    * Defaults to None

earliest_time_offset = [integer]
    * Time in seconds before event time that the search should cover

latest_time_offset = [integer]
    * Time in seconds after event time that the search should cover

