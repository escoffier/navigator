VERSION = 0.1.0

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDFLAGS = '-extldflags "-static"'
endif

REPOPREFIX?=localhost:32000
REPOPREFIXOLD?=localhost:32000

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
	# @if [ "$$(command -v revive)" ]; then \
	# 		echo "revive ./..."; \
	# 		revive ./...; \
	# 		test -z "$$(revive ./...)"; \
	# else \
	# 		echo "golint -set_exit_status ./..."; \
	# 		golint -set_exit_status ./...; \
	# fi
	# @if [ -x "$$(command -v golangci-lint)" ]; then \
	# 		echo "golangci-lint run --fix"; \
	# 		golangci-lint run --fix; \
	# fi
	go test $(TAGS) -v -race -cover -count=1 ./...

.PHONY: clean
clean:				## Clean all artifacts
	@echo "+ $@"
	rm -fr dist

.PHONY: scap-jobs
scap-jobs:
	cd configs/scap/jobs/kube-bench && \
		$(MAKE) DOCKER_REGISTRY=$(REPOPREFIX)/ VERSION=latest build-docker 
	cd configs/scap/jobs/docker-bench-security && \
		docker build -t $(REPOPREFIX)/docker-bench-security:latest .
	cd configs/scap/jobs/host-bench && \
		docker build -t $(REPOPREFIX)/host-bench:latest .

.PHONY: console
console: generate 		## Build console binary
	# This target depends on scap-jobs, but for optimisation, if we want to build only console, they won't be built.
	# To build all targets, use make all.
	@echo "+ $@"
	go build  -a \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/console/cmd.Version=$(VERSION)" \
		-o dist/vegeta-console gitlab.com/piccolo_su/vegeta/cmd/console
	docker build -t $(REPOPREFIX)/tensorsec-console:latest -f ./build/console/Dockerfile .

.PHONY: scanner
scanner: generate		## Build scanner binary
	@echo "+ $@"
	go build -a \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd.Version=$(VERSION)" \
		-o dist/vegeta-scanner gitlab.com/piccolo_su/vegeta/cmd/scanner
	docker build -t $(REPOPREFIX)/tensorsec-scanner:latest -f ./build/scanner/Dockerfile .

.PHONY: tensoragent
tensoragent: generate ## Build tensoragent binary
	@echo "+ $@"
	go build -v -a \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/tensoragent/cmd.Version=$(VERSION)" \
		-o dist/tensoragent gitlab.com/piccolo_su/vegeta/cmd/tensoragent
	docker build -t $(REPOPREFIX)/tensoragent:latest -f ./build/tensoragent/Dockerfile .

.PHONY: tensordig
tensordig: generate ## Build tensordig binary
	@echo "+ $@"
	docker build -t $(REPOPREFIX)/tensordig:latest  -f ./build/tensordig/Dockerfile --build-arg LDFLAGS=$(LDFLAGS) --build-arg VERSION=$(VERSION) .

.PHONY: all
all: scanner scap-jobs console tensoragent tensordig

.PHONY: pushimages
pushimages:
	docker push $(REPOPREFIX)/tensorsec-console:latest
	docker push $(REPOPREFIX)/tensorsec-scanner:latest
	docker push $(REPOPREFIX)/kube-bench:latest
	docker push $(REPOPREFIX)/docker-bench-security:latest
	docker push $(REPOPREFIX)/host-bench:latest
	docker push $(REPOPREFIX)/tensoragent:latest
	docker push $(REPOPREFIX)/tensordig:latest

.PHONY: retag
retag:
	docker tag $(REPOPREFIXOLD)/tensorsec-console:latest $(REPOPREFIX)/tensorsec-console:latest
	docker tag $(REPOPREFIXOLD)/tensorsec-scanner:latest $(REPOPREFIX)/tensorsec-scanner:latest
	docker tag $(REPOPREFIXOLD)/kube-bench:latest $(REPOPREFIX)/kube-bench:latest
	docker tag $(REPOPREFIXOLD)/docker-bench-security:latest $(REPOPREFIX)/docker-bench-security:latest
	docker tag $(REPOPREFIXOLD)/host-bench:latest $(REPOPREFIX)/host-bench:latest
	docker tag $(REPOPREFIXOLD)/tensoragent:latest $(REPOPREFIX)/tensoragent:latest
	docker tag $(REPOPREFIXOLD)/tensordig:latest $(REPOPREFIX)/tensordig:latest

.PHONY: redeploy
redeploy:
	# Note, if you get:
	# Error: release tensorsec failed: object is being deleted: persistentvolumeclaims "tensorsec-mongodb" already exists
	# then run this target again.
	@echo "+ $@"
	cd deployments/helm; \
		helm delete --purge tensorsec; \
		rm -rf charts; \
		helm dep up; \
		helm install ./ --namespace tensorsec --name tensorsec; \
		cd -
