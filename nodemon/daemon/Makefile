.PHONY: help
help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY: build
build:			## Build daemon tarball
	@echo "+ $@"
	python setup.py sdist

.PHONY: clean
clean:			## Clean the project
	@echo "+ $@"
	rm -fr dist *.egg-info
