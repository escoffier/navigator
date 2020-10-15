## Build

### Prepare environment

1. Install golang (I have v1.15.1)
2. Install build tools

```bash
sudo apt-get install make gcc npm python python-setuptools
go get -u github.com/swaggo/swag/cmd/swag
go get -u golang.org/x/lint/golint
```

3. Run npm install for the first time:

```bash
cd cmd/console/install; npm install; cd -;
```

### Build

Build bins and npm and put under dist/. Then creates docker images.

```bash
make all
```

*Note: all docker image tags are prefixed with REPOPREFIX, see Makefile. By default, this variable points to local repo managed by microk8s.*

You can also be more specific with what you want to build. 
See dependencies of `all` recipe to see what components are available to build.

*Note: `Console` target has some dependencies, but they will only be built in
`all` target. This is to make it quicker to iterate on `Console`.*

## Push

Pushes all modified images to docker registry.

```bash
make pushimages
```

*Note: uses docker image tag prefix REPOPREFIX, see Makefile.*

Pushing to our docker registry:

```bash
# Add insecure registries entry to daemon.json:
# vi /var/snap/docker/current/config/daemon.json
#"insecure-registries": ["registry.t-appagile.com"],

# Login to docker registry
docker login registry.t-appagile.com/

# Retag images from local to remote registry
REPOPREFIX=registry.t-appagile.com/tensorsecurity REPOPREFIXOLD=localhost:32000 make retag

# Push retagged images
REPOPREFIX=registry.t-appagile.com/tensorsecurity make pushimages
```
