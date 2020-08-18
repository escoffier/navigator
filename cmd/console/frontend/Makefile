.PHONY: help
help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY: clean
clean:				## Clean all frontend artifacts
	@echo "+ $@"
	rm -fr dist
	rm -fr node_modules

.PHONY: build
build: init			## Build frontend and save to dist/ui
	@echo "+ $@"
	npm run build

.PHONY: init
init:				## Init node modules for frontend
	@echo "+ $@"
	npm update
