#!/usr/bin/env python
# encoding = utf-8
# Always put this line at the beginning of this file
import da_ess_contentupdate_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_escu_investigate_helper

class AlertActionWorkerescu_investigate(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkerescu_investigate, self).__init__(ta_name, alert_name)

    def validate_params(self):
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            self.prepare_meta_for_cam()

            if not self.validate_params():
                return 3
            status = modalert_escu_investigate_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(ae.message))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e.message:
                self.log_error(msg.format(e.message))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkerescu_investigate("DA-ESS-ContentUpdate", "escu_investigate").run(sys.argv)
    sys.exit(exitcode)
