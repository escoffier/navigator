tar -xvzf /tmp/docker-19.03.9.tgz -C /tmp/
/tmp/docker/docker -H unix:///custom/docker/docker.sock ps
/tmp/docker/docker -H unix:///custom/docker/docker.sock images
