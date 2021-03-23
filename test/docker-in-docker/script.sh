curl -o /tmp/docker-19.03.9.tgz https://download.docker.com/linux/static/stable/x86_64/docker-19.03.9.tgz
tar -xvzf /tmp/docker-19.03.9.tgz -C /tmp/
/tmp/docker/docker -H unix:///custom/docker/docker.sock ps
/tmp/docker/docker -H unix:///custom/docker/docker.sock images
