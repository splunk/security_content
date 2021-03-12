import json
from datetime import datetime
from datetime import timedelta
from pytz import timezone 
import fileinput
import os
import re
import io

class DataManipulation:

    def manipulate_timestamp(self, file_path, sourcetype, source):

        if source == 'WinEventLog:Security':
            self.manipulate_timestamp_windows_event_log_raw(file_path)


    def manipulate_timestamp_windows_event_log_raw(self, file_path):
        path = file_path

        f = io.open(path, "r", encoding="utf-8")
        pst = timezone('US/Pacific')
        self.now = datetime.now(pst)
        self.now = self.now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self.now = datetime.strptime(self.now,"%Y-%m-%dT%H:%M:%S.%fZ")

        # read raw logs
        regex = r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M'
        data = f.read()
        lst_matches = re.findall(regex, data)
        if len(lst_matches) > 0:
            latest_event  = datetime.strptime(lst_matches[-1],"%m/%d/%Y %I:%M:%S %p")
            self.difference = self.now - latest_event
            f.close()

            result = re.sub(regex, self.replacement_function, data)

            with io.open(path + ".swp", "w+", encoding='utf8') as f:
                f.write(result)
        else:
            f.close()
            return


    def replacement_function(self, match):
        try:
            event_time = datetime.strptime(match.group(),"%m/%d/%Y %I:%M:%S %p")
            new_time = self.difference + event_time
            return new_time.strftime("%m/%d/%Y %I:%M:%S %p")
        except Exception as e:
            return match.group()
