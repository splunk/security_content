
[<stanza name>]
* Create a unique stanza name for each saved search that belongs to an analytic story
* Follow the stanza name with any number of the following settings.
* If you do not specify a setting, Splunk software uses the default.

action.escu.full_search_name = <string>
	* Full name of the search
	* required

action.escu.mappings = [json]
	* Framework mappings like CIS, Kill Chain, NIST, ATTACK

action.escu.analytic_story = <list>
	* List of analytic story the search belongs to

action.escu.search_type = [detection | investigative | support]
	* The type of this search