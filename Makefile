VERSION = 0.1.0

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDFLAGS = '-extldflags "-static"'
endif

REPOPREFIX=localhost:32000/

.PHONY: help
help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY: dev
dev:				## Check your dev tools
	@echo "+ $@"
	@command -v pre-commit || echo "pre-commit: not found, pip install pre-commit"
	@command -v swag || echo "swag: not found, go get -u github.com/swaggo/swag/cmd/swag"
	@command -v revive || echo "revive: not found, go get -u github.com/mgechev/revive"
	@command -v golangci-lint || \
		echo "golangci-lint: not found, check https://github.com/golangci/golangci-lint"
	@command -v npm || echo "npm: not found, check https://nodejs.org/en/dotelewnload/"
	@test -e .git/hooks/pre-commit || echo "pre-commit hook is not installed: pre-commit install"

.PHONY: generate
generate:
	@echo "+ $@"
	cd cmd/console; go generate; cd -
	cd cmd/scanner; go generate; cd -

.PHONY: test
test: generate			## Run golint, staticcheck, and go test for all the sub-directories
	@echo "+ $@"
	go mod tidy
	@if [ "$$(command -v revive)" ]; then \
			echo "revive ./..."; \
			revive ./...; \
			test -z "$$(revive ./...)"; \
	else \
			echo "golint -set_exit_status ./..."; \
			golint -set_exit_status ./...; \
	fi
	@if [ -x "$$(command -v golangci-lint)" ]; then \
			echo "golangci-lint run --fix"; \
			golangci-lint run --fix; \
	fi
	go test $(TAGS) -v -race -cover -count=1 ./...

.PHONY: clean
clean:				## Clean all artifacts
	@echo "+ $@"
	$(MAKE) -C alerter clean
	$(MAKE) -C nodemon/daemon clean
	$(MAKE) -C nodemon/scanner clean
	$(MAKE) -C cmd/console/frontend clean
	rm -fr dist

.PHONY: console
console: generate frontend		## Build console binary
	@echo "+ $@"
	go build -a \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/console/cmd.Version=$(VERSION)" \
		-o dist/vegeta-console gitlab.com/piccolo_su/vegeta/cmd/console
	docker build -t $(REPOPREFIX)vegeta-console:latest -f ./build/console/Dockerfile .

.PHONY: alerter
alerter:			## Build alerter tarball
	@echo "+ $@"
	$(MAKE) -C alerter build
	docker build -t $(REPOPREFIX)vegeta-alerter:latest -f ./build/alerter/Dockerfile .

.PHONY: daemon
daemon:				## Build daemon tarball
	@echo "+ $@"
	$(MAKE) -C nodemon/daemon build
	docker build -t $(REPOPREFIX)vegeta-daemon:latest -f ./build/daemon/Dockerfile .

.PHONY: scanner
scanner: generate		## Build scanner binary
	@echo "+ $@"
	go build -a \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd.Version=$(VERSION)" \
		-o dist/vegeta-scanner gitlab.com/piccolo_su/vegeta/cmd/scanner
	docker build -t $(REPOPREFIX)vegeta-scanner:latest -f ./build/scanner/Dockerfile .

.PHONY: scap
scap:				## Build scap binary
	@echo "+ $@"
	go build -a \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/scap/Version=$(VERSION)" \
		-o dist/vegeta-scap gitlab.com/piccolo_su/vegeta/cmd/scap
	docker build -t $(REPOPREFIX)vegeta-scap:latest -f ./build/scap/Dockerfile .

.PHONY: all
all: scap scanner console daemon alerter

.PHONY: pushimages
pushimages:
	docker push localhost:32000/vegeta-console
	docker push localhost:32000/vegeta-scanner
	docker push localhost:32000/vegeta-scap
	docker push localhost:32000/vegeta-daemon
	docker push localhost:32000/vegeta-alerter

.PHONY: frontend
frontend:			## Build frontend
	@echo "+ $@"
	$(MAKE) -C cmd/console/frontend build
	rm -fr dist/ui
	mkdir -p dist/ui
	cp -r cmd/console/frontend/dist/* dist/ui/

.PHONY: redeploy
redeploy:
	@echo "+ $@"
	cd deployments/helm; \
		microk8s helm delete --purge vegeta; \
		microk8s helm dep up; \
		microk8s helm install ./ --namespace vegeta --name vegeta; \
		cd -
