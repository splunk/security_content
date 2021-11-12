import datetime
import docker
import timeit

def setup_image(client: docker.client.DockerClient, reuse_images: bool, container_name: str) -> None:
    if not reuse_images:
        #Check to see if the image exists.  If it does, then remove it.  If it does not, then do nothing
        docker_image = None
        try:
            docker_image = client.images.get(container_name)
        except Exception as e:
            #We don't need to do anything, the image did not exist on our system
            print("Image named [%s] did not exist, so we don't need to try and remove it."%(container_name))
        if docker_image != None:
            #We found the image.  Let's try to delete it
            print("Found docker image named [%s] and you have requested that we forcefully remove it"%(container_name))
            try:
                client.images.remove(image=container_name, force=True, noprune=False)
                print("Docker image named [%s] forcefully removed"%(container_name))
            except Exception as e:
                print("Error forcefully removing [%s]"%(container_name))
                raise(e)
    
    #See if the image exists.  If it doesn't, then pull it from Docker Hub
    docker_image = None
    try:
        docker_image = client.images.get(container_name)
        print("Docker image [%s] found, no need to download it."%(container_name))
    except Exception as e:
        #Image did not exist on the system
        docker_image = None

    if docker_image is None:
        #We did not find the image, so pull it
        try:
            print("Downloading image [%s].  Please note "
                 "that this could take a long time depending on your "
                 "connection. It's around 2GB."%(container_name))
            pull_start_time = timeit.default_timer()
            client.images.pull(container_name)
            pull_finish_time = timeit.default_timer()
            print("Successfully pulled the docker image [%s] in %ss"%
                  (container_name,
                  datetime.timedelta(seconds=pull_finish_time - pull_start_time, microseconds=0) ))

        except Exception as e:
            print("There was an error trying to pull the image [%s]: [%s]"%(container_name,str(e)))
            raise(e)


