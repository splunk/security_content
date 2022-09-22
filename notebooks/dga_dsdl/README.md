Deploying DGA model in Splunk App for Data Science and Deep Learning (DSDL) 
===========================================================================

### Set up of the DSDL app


1. Install the DSDL app on Splunk instance and follow the steps outlined in the Overview > User Guide.
2. Additional information and FAQs are available here https://splunkbase.splunk.com/app/4607/#/details

### Download the model artifacts - notebooks, binaries

1. Download the artifacts .tar.gz file from S3 bucket https://splunk-seal.s3.us-west-2.amazonaws.com/pretrained_dga_detection_dga_model_dltk.tar.gz

### Deploy the model artifacts

1. Login into Splunk instance, launch DSDL app.
2. Select Containers and it should list all the containers.
3. Select Container Image as Golden image 3.9 and Cluster target as per env setup and start the dga_model_dltk container.
4. Wait for the container to start up and urls to populate for the container.
5. Login into the dga_model_dltk container Jupyter lab url ex: https://{container_url}:port_num/lab? 
   *Use the password provided in the Overview > User Guide of DSDL app
6. The below steps are performed within the Jupyter Lab.
    * Upload the pretrained_dga_detection_dga_model_dltk.tar.gz file into app/model/data path using the upload option in the jupyter notebook.
    * Open a terminal on Jupyterlab and execute the following commands
   			* Untar the artifact pretrained_dga_detection_dga_model_dltk.tar.gz
				```
				tar -xf app/model/data/pretrained_dga_detection_dga_model_dltk.tar.gz -C app/model/data
				```
	* Upload {confirm_path}notebook pretrained_dga_detection.ipynb into jupyter lab notebooks folder using the upload option in Jupyter lab and save the notebook using the save option in jupyter notebook.
    * Upload dga_model_dltk.json into notebooks/data folder.
 7. The dga detection model dga_model_dltk is now deployed within DSDL.