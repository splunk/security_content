Deploying DGA model in Splunk App for Data Science and Deep Learning (DSDL) 
===========================================================================

### Set up of the DSDL app


1. Start the docker daemon 
2. Install the DSDL app on Splunk instance and follow the steps outlined in the Overview > User Guide  (Overview drop down menu  in the DSDL app)
3. Additional information and FAQs are available here https://splunkbase.splunk.com/app/4607/#/details

### Download the artifacts - notebooks, binaries

1. Download the artifacts .tar.gz file from S3 bucket https://splunk-seal.s3.us-west-2.amazonaws.com/pretrained_dga_detection_dga_model_dltk.tar.gz

### Deploy the artifacts

1. Login into Splunk instance, launch DSDL app.
2. Select Containers and it should list all the containers.
3. Select the Golden image 3.9 and type of cluster - docker/kubernetes and start the dev container 
4. Wait for the container to start up and populate urls for the container
5. Login into the __dev__ container jupyter lab url ex: https://<container-url>:8888/lab? (Password: Splunk4DeepLearning)
6. Open a terminal on Jupyterlab and  execute the following commands
* Upload the pretrained_dga_detection_dga_model_dltk.tar.gz file into app/model/data using the upload option in the jupyter notebook
* Untar the artifact pretrained_dga_detection_dga_model_dltk.tar.gz
```
tar -xf app/model/data/pretrained_dga_detection_dga_model_dltk.tar.gz -C app/model/data
```
* Upload notebook pretrained_dga_detection.ipynb into notebooks/ using the upload in Jupyter notebook and save the notebook using the save option in jupyter notebook 
* Upload dga_model_dltk.json into notebooks/data folder

 7. The .mlmlmodel is an essential file that contains information about the pretrained model. To make the pre-trained model available, the model spec files need to be placed in the lookup of mltk-container under etc/apps. 
 * Place __mlspl_dga_model_dltk.mlmodel into install_path_of_splunk/etc/apps/mltk-container/lookups

 8. Restart splunk server
 9. Relaunch the DSDL app, select the Containers menu. Select Golden image, suitable environment - either Docker or Kubernetes and select the specific container with the name and Start the container.

### Applying pretrained model into DSDL
Run the search 'Detect DGA domains using Pretrained Deep Learning Model in DLTK' and search should run successfully without errors.
