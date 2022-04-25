
import splunklib.client as client
import multiprocessing
import http.server
import time

class Deploy:
    def __init__(self, args):
        self.username = args.username
        self.password = args.password
        self.host = args.search_head_address
        self.api_port = args.api_port
        self.path = args.path
        self.overwrite_app = args.overwrite_app
        self.server_app_path=f"http://192.168.0.187:9998/args.path"

        self.http_process = self.start_http_server()

        self.install_app()

    def start_http_server(self, http_address:str ='', http_listen_port:int=9998) -> multiprocessing.Process:
        httpd = http.server.HTTPServer((http_address, http_listen_port), http.server.BaseHTTPRequestHandler)
        m = multiprocessing.Process(target=httpd.serve_forever)
        m.start()
        return m
        


    def install_app(self) -> bool:
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
    
    
    