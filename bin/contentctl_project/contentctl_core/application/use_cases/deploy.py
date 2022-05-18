import splunklib.client as client
import multiprocessing
import http.server
import time
import sys
import subprocess
import os
class Deploy:
    def __init__(self, args):

        
        
        #First, check to ensure that the legal ack is correct. If not, quit
        if args.acs_legal_ack != "Y":
            raise(Exception(f"Error - must supply 'acs-legal-ack=Y', not 'acs-legal-ack={args.acs_legal_ack}'"))
        
        self.acs_legal_ack = args.acs_legal_ack
        self.app_package = args.app_package
        if not os.path.exists(self.app_package):
            raise(Exception(f"Error - app_package file {self.app_package} does not exist"))
        self.username = args.username
        self.password = args.password
        self.server = args.server

        
       
        self.deploy_to_splunk_cloud()
        #self.http_process = self.start_http_server()

        #self.install_app()

    
    def deploy_to_splunk_cloud(self):
        
        commandline = f"acs apps install private --acs-legal-ack={self.acs_legal_ack} "\
                f"--app-package {self.app_package} --server {self.server} --username "\
                f"{self.username} --password {self.password}"
        
        
        try:
            res = subprocess.run(args = commandline.split(' '), )    
        except Exception as e:
            raise(Exception(f"Error deploying to Splunk Cloud Instance: {str(e)}"))
        print(res.returncode)
        if res.returncode != 0:
            raise(Exception("Error deploying to Splunk Cloud Instance. Review output to diagnose error."))

    '''
    def install_app_local(self) -> bool:
        #Connect to the service
        time.sleep(1)
        #self.http_process.start()
        #time.sleep(2)
        

        print(f"Connecting to server {self.host}")
        try:
            service = client.connect(host=self.host, port=self.api_port, username=self.username, password=self.password)
            assert isinstance(service, client.Service)
            
        except Exception as e:
            raise(Exception(f"Failure connecting the Splunk Search Head: {str(e)}"))
            
        
        #Install the app
        try:
            params = {'name': self.server_app_path}
            res = service.post('apps/appinstall', **params)
            #Check the result?

            print(f"Successfully installed {self.server_app_path}!")



        except Exception as e:
            raise(Exception(f"Failure installing the app {self.server_app_path}: {str(e)}"))

        
        #Query and list all of the installed apps
        try:
            all_apps = service.apps
        except Exception as e:
            print(f"Failed listing all apps: {str(e)}")
            return False

        print("Installed apps:")
        for count, app in enumerate(all_apps):
            print("\t{count}.  {app.name}")   


        print(f"Installing app {self.path}")

        self.http_process.terminate()

        return True
    '''
    
    