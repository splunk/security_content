from distutils.command.install_data import install_data
import splunklib.client as client


class Deploy:
    def __init__(self, args):
        self.username = args.username
        self.password = args.password
        self.host = args.host
        self.api_port = args.api_port
        self.path = args.path
        self.overwrite_app = args.overwrite_app
        self.install_app()

    def install_app(self) -> bool:
        #Connect to the service
        try:
            service = client.connect(host=self.host, port=self.api_port, username=self.username, password=self.password)
            assert isinstance(service, client.Service)


        except Exception as e:
            print(f"Failure connecting the the Splunk Search Head: {str(e)}")
            return False
        
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
        return True
    
    
    