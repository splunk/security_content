import json
from datetime import datetime
from datetime import timedelta
#import fileinput
import os
import re
import io

class DataManipulation:

    def manipulate_timestamp(self, file_path, sourcetype, source):


        #print('Updating timestamps in attack_data before replaying')

        if sourcetype == 'aws:cloudtrail':
            self.manipulate_timestamp_cloudtrail(file_path)

        if source == 'WinEventLog:System' or source == 'WinEventLog:Security':
            self.manipulate_timestamp_windows_event_log_raw(file_path)

        if source == 'exchange':
            self.manipulate_timestamp_exchange_logs(file_path)


    def manipulate_timestamp_exchange_logs(self, file_path):
        path =  os.path.join(os.path.dirname(__file__), '../' + file_path)
        path =  path.replace('modules/../','')

        f = io.open(path, "r", encoding="utf-8")

        first_line = f.readline()
        d = json.loads(first_line)
        latest_event  = datetime.strptime(d["CreationTime"],"%Y-%m-%dT%H:%M:%S")

        now = datetime.now()
        now = now.strftime("%Y-%m-%dT%H:%M:%S")
        now = datetime.strptime(now,"%Y-%m-%dT%H:%M:%S")

        difference = now - latest_event
        f.close()

        #Mimic the behavior of fileinput but in a threadsafe way
        #Rename the file, which fileinput does for inplace.
        #Note that path will now be the new file
        original_backup_file = f"{path}.bak"    
        os.rename(path, original_backup_file)
        
        with open(original_backup_file, "r") as original_file:
            with open(path, "w") as new_file:
                for line in original_file:
                    d = json.loads(line)
                    original_time = datetime.strptime(d["CreationTime"],"%Y-%m-%dT%H:%M:%S")
                    new_time = (difference + original_time)

                    original_time = original_time.strftime("%Y-%m-%dT%H:%M:%S")
                    new_time = new_time.strftime("%Y-%m-%dT%H:%M:%S")
                    #There is no end character appended, no need for end=''
                    new_file.write(line.replace(original_time, new_time))


        os.remove(original_backup_file)

    def manipulate_timestamp_windows_event_log_raw(self, file_path):
        path =  os.path.join(os.path.dirname(__file__), '../' + file_path)
        path =  path.replace('modules/../','')

        f = io.open(path, "r", encoding="utf-8")
        self.now = datetime.now()
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

            with io.open(path, "w+", encoding='utf8') as f:
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
            self.logger.error("Error in timestamp replacement occured: " + str(e))
            return match.group()


    def manipulate_timestamp_cloudtrail(self, file_path):
        path =  os.path.join(os.path.dirname(__file__), '../' + file_path)
        path =  path.replace('modules/../','')

        f = io.open(path, "r", encoding="utf-8")

        try:
            first_line = f.readline()
            d = json.loads(first_line)
            latest_event  = datetime.strptime(d["eventTime"],"%Y-%m-%dT%H:%M:%S.%fZ")

            now = datetime.now()
            now = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            now = datetime.strptime(now,"%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            first_line = f.readline()
            d = json.loads(first_line)
            latest_event  = datetime.strptime(d["eventTime"],"%Y-%m-%dT%H:%M:%SZ")

            now = datetime.now()
            now = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            now = datetime.strptime(now,"%Y-%m-%dT%H:%M:%SZ")

        difference = now - latest_event
        f.close()



        #Mimic the behavior of fileinput but in a threadsafe way
        #Rename the file, which fileinput does for inplace.
        #Note that path will now be the new file
        original_backup_file = f"{path}.bak"    
        os.rename(path, original_backup_file)
        
        with open(original_backup_file, "r") as original_file:
            with open(path, "w") as new_file:
                for line in original_file:
                    try:
                        d = json.loads(line)
                        original_time = datetime.strptime(d["eventTime"],"%Y-%m-%dT%H:%M:%S.%fZ")
                        new_time = (difference + original_time)

                        original_time = original_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                        new_time = new_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                        new_file.write(line.replace(original_time, new_time))
                    except ValueError:
                        d = json.loads(line)
                        original_time = datetime.strptime(d["eventTime"],"%Y-%m-%dT%H:%M:%SZ")
                        new_time = (difference + original_time)

                        original_time = original_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                        new_time = new_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                        new_file.write(line.replace(original_time, new_time))


        os.remove(original_backup_file)