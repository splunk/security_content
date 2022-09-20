Deploying DGA model in Splunk App for Data Science and Deep Learning (DSDL) 
===========================================================================

### Set up of the DSDL app


1. Start the docker daemon 
2. Install the DSDL app on Splunk instance and follow the steps outlined in the Overview > User Guide  (Overview drop down menu  in the DSDL app)
3. Additional information and FAQs are available here https://splunkbase.splunk.com/app/4607/#/details

### Download the model artifacts - notebooks, binaries

1. Download the artifacts .tar.gz file from S3 bucket https://splunk-seal.s3.us-west-2.amazonaws.com/pretrained_dga_detection_dga_model_dltk.tar.gz

### Deploy the model artifacts

1. Login into Splunk instance, launch DSDL app.
2. Select Containers and it should list all the containers.
3. Select Container Image as Golden image 3.9 and Cluster target as per env setup and start the dev container.
4. Wait for the container to start up and urls to populate for the container.
5. Login into the __dev__ container jupyter lab url ex: https://<container-url>:8888/lab?
6. Open a terminal on Jupyterlab and  execute the following commands
   * Upload the pretrained_dga_detection_dga_model_dltk.tar.gz file into app/model/data using the upload option in the jupyter notebook.
   * Untar the artifact pretrained_dga_detection_dga_model_dltk.tar.gz
		```
		tar -xf app/model/data/pretrained_dga_detection_dga_model_dltk.tar.gz -C app/model/data
		```
   * Upload notebook pretrained_dga_detection.ipynb into notebooks folder using the upload option in Jupyter lab and save the notebook using the save option in jupyter notebook.
   * Upload dga_model_dltk.json into notebooks/data folder.

 7. Refresh the DSDL app, select the Containers menu.
 8. Select Container Image as Golden image 3.9 and Cluster target as per env setup and start the new container dga_model_dltk.
 9. Select the container and click Start. 
 10. The dga detection model dga_model_dltk is now deployed within DLTK.