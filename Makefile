VERSION = 0.1.0

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDFLAGS = '-extldflags "-static"'
endif

REPOPREFIX?=localhost:32000
REPOPREFIXOLD?=localhost:32000

USEMIRROR?=true

RELEASEVERSION?=v0.0.1

FETCHTAG?=latest

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

.PHONY: host-bench-base
host-bench-base:
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	cd configs/scap/jobs/host-bench && \
		docker build -t $(REPOPREFIX)/baseimage-host-bench:latest \
    	--build-arg REPO=$(REPOPREFIX) --build-arg MIRROR=mirrors.aliyun.com -f ./baseimage-dockerfile .
else
	cd configs/scap/jobs/host-bench && \
		docker build -t $(REPOPREFIX)/baseimage-host-bench:latest \
    	--build-arg REPO=$(REPOPREFIX) -f ./baseimage-dockerfile .
endif

.PHONY: scap-jobs
scap-jobs:
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "scap-jobs will use mirror"
	cd tensor-compliance-check/kube-bench && \
		docker build -t $(REPOPREFIX)/kube-bench:latest \
			--build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
	cd tensor-compliance-check/docker-bench-security && \
		docker build -t $(REPOPREFIX)/docker-bench-security:latest \
			--build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
	cd tensor-compliance-check/host-bench && \
		docker build -t $(REPOPREFIX)/host-bench:latest \
			--build-arg MIRROR=mirrors.aliyun.com --build-arg REPO=$(REPOPREFIX) .
else
	@echo "scap-jobs will not use mirror"
	cd tensor-compliance-check/kube-bench && \
		$(MAKE) DOCKER_REGISTRY=$(REPOPREFIX)/ VERSION=latest build-docker
	cd tensor-compliance-check/docker-bench-security && \
		docker build -t $(REPOPREFIX)/docker-bench-security:latest .
	cd tensor-compliance-check/host-bench && \
		docker build --build-arg REPO=$(REPOPREFIX) -t $(REPOPREFIX)/host-bench:latest .
endif

.PHONY: console
console: generate 		## Build console binary
	# This target depends on scap-jobs, but for optimisation, if we want to build only console, they won't be built.
	# To build all targets, use make all.
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/console/cmd.Version=$(VERSION)" \
		-o dist/console gitlab.com/piccolo_su/vegeta/cmd/console
	docker build -t $(REPOPREFIX)/console:latest -f ./build/console/Dockerfile .

.PHONY: data-base
data-base: ## Build data base image
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	docker build -t $(REPOPREFIX)/baseimage-data:latest \
    --build-arg MIRROR=mirrors.aliyun.com -f ./build/data/baseimage-dockerfile .
else
	docker build -t $(REPOPREFIX)/baseimage-data:latest \
    -f ./build/data/baseimage-dockerfile .
endif

.PHONY: data
data: generate 		## Build cleaner binary
	@echo "+ $@"
	CGO_ENABLED=0 go build -v \
		-o dist/cleaner gitlab.com/piccolo_su/vegeta/cmd/data/tool/main
	docker build -t $(REPOPREFIX)/cleaner:latest --build-arg REPO=$(REPOPREFIX) -f ./build/data/Dockerfile  --build-arg MIRROR=mirrors.aliyun.com .

.PHONY: kube-hunter-report
kube-hunter-report: generate
	@echo "+ $@"
	CGO_ENABLED=0 go build -v \
    		-o dist/kube-hunter-report gitlab.com/piccolo_su/vegeta/cmd/kube-hunter-report
	docker build -t $(REPOPREFIX)/kube-hunter-report:latest --build-arg REPO=$(REPOPREFIX) -f ./build/kube-hunter-report/Dockerfile .

.PHONY: platform-report
platform-report: generate
	@echo "+ $@"
	CGO_ENABLED=0 go build -v \
    		-o dist/platform-report gitlab.com/piccolo_su/vegeta/cmd/platform-report
	docker build -t $(REPOPREFIX)/platform-report:latest --build-arg REPO=$(REPOPREFIX) -f ./build/platform-report/Dockerfile .

.PHONY: scanner-base
scanner-base: ## Build scanner base image
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	docker build -t $(REPOPREFIX)/baseimage-scanner:latest \
    --build-arg REPO=$(REPOPREFIX) --build-arg MIRROR=mirrors.aliyun.com -f ./build/scanner/baseimage-dockerfile .
else
	docker build -t $(REPOPREFIX)/baseimage-scanner:latest \
    --build-arg REPO=$(REPOPREFIX) -f ./build/scanner/baseimage-dockerfile .
endif

.PHONY: webshell-server
webshell-server: 		## Build cleaner binary
	@echo "+ $@"
	CGO_ENABLED=1 go build -v \
		-o dist/webshell-server cmd/webshell-server/cmd/main.go
	docker build -t $(REPOPREFIX)/webshell-server:latest -f ./build/webshell-server/Dockerfile .

.PHONY: scanner-cicd
scanner-cicd: generate
	echo "+ $@"
	go build -v \
                --ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd/cmd.Version=$(VERSION)" \
                -o dist/scanner-cicd gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd

.PHONY: safe-node-image
safe-node-image: generate
	echo "+ $@"
	go build -v  -o dist/safe-node-image  cmd/scripts/safe-node-image/main.go
	docker build -t $(REPOPREFIX)/safe-node-image:latest -f ./build/safe-node-image/Dockerfile .

.PHONY: scanner
scanner: generate		## Build scanner binary
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd.Version=$(VERSION)" \
		-o dist/scanner gitlab.com/piccolo_su/vegeta/cmd/scanner
	docker build -t $(REPOPREFIX)/scanner:latest --build-arg REPO=$(REPOPREFIX) -f ./build/scanner/Dockerfile .

.PHONY: faulty-base
faulty-base: ## Build faulty base image
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	docker build -t $(REPOPREFIX)/baseimage-faulty:latest \
    --build-arg MIRROR=mirrors.aliyun.com -f ./build/faulty/baseimage-dockerfile .
else
	docker build -t $(REPOPREFIX)/baseimage-faulty:latest \
    -f ./build/faulty/baseimage-dockerfile .
endif

.PHONY: daemon
daemon: ## Build daemon binary
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "daemon will use mirror"
	go build -v -o bin/daemon  cmd/daemon/main.go
	docker build -f build/daemon/Dockerfile -t $(REPOPREFIX)/daemon:latest \
        --build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
else
	@echo "daemon will use mirror"
	go build -v -o bin/daemon  cmd/daemon/main.go
	docker build -f build/daemon/Dockerfile -t $(REPOPREFIX)/daemon:latest .
endif


.PHONY: scarecrow
scarecrow:   ## Build scarecrow docker to test CVEs
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "scarecrow will use mirror"
	docker build -t $(REPOPREFIX)/scarecrow:latest -f ./build/scarecrow/Dockerfile \
		--build-arg MIRROR=mirrors.aliyun.com --build-arg TAG=$(RELEASEVERSION) .
else
	@echo "scarecrow will not use mirror"
	docker build -t $(REPOPREFIX)/scarecrow:latest -f ./build/scarecrow/Dockerfile \
		--build-arg TAG=$(RELEASEVERSION) .
endif


.PHONY: faulty
faulty: drift-prevention-client     ## Build faulty docker to test CVEs
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "faulty will use mirror"
	docker build -t $(REPOPREFIX)/faulty:latest -f ./build/faulty/Dockerfile \
		--build-arg MIRROR=mirrors.aliyun.com --build-arg REPO=$(REPOPREFIX) --build-arg TAG=$(FETCHTAG) .
else
	@echo "faulty will not use mirror"
	docker build -t $(REPOPREFIX)/faulty:latest -f ./build/faulty/Dockerfile --build-arg TAG=$(FETCHTAG) \
		--build-arg REPO=$(REPOPREFIX) .
endif

.PHONY: drift-prevention-client-base
drift-prevention-client-base: ## Build drift-prevention-client base image
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	docker build -t $(REPOPREFIX)/baseimage-drift-prevention-client:latest \
    --build-arg MIRROR=mirrors.aliyun.com -f ./build/drift-prevention-client/baseimage-dockerfile .
else
	docker build -t $(REPOPREFIX)/baseimage-drift-prevention-client:latest \
    -f ./build/drift-prevention-client/baseimage-dockerfile .
endif

.PHONY: drift-prevention-client
drift-prevention-client:	## Build drift prevention client binary
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	(cd configs/drift-prevention && ./run.sh mirrors.aliyun.com)
	go build -v -a -o dist/file-checker cmd/file-checker/main.go
	@echo "drift-prevention-client will use mirror"
	docker build -t $(REPOPREFIX)/drift-prevention-client:latest -f ./build/drift-prevention-client/Dockerfile \
		--build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com --build-arg REPO=$(REPOPREFIX) .
	docker tag $(REPOPREFIX)/drift-prevention-client:latest $(REPOPREFIX)/drift-prevention-client:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/drift-prevention-client:$(RELEASEVERSION)
else
	@echo "drift-prevention-client will not use mirror"
	(cd configs/drift-prevention && ./run.sh)
	go build -v -a -o dist/file-checker cmd/file-checker/main.go
	docker build -t $(REPOPREFIX)/drift-prevention-client:latest -f ./build/drift-prevention-client/Dockerfile --build-arg REPO=$(REPOPREFIX) .
	docker tag $(REPOPREFIX)/drift-prevention-client:latest $(REPOPREFIX)/drift-prevention-client:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/drift-prevention-client:$(RELEASEVERSION)
endif

.PHONY: security-profiles-webhook
security-profiles-webhook:     ## Build security-profiles-webhook docker
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/security-profiles-webhook/cmd.Version=$(VERSION)" \
		-o dist/security-profiles-webhook gitlab.com/piccolo_su/vegeta/cmd/security-profiles-webhook
	docker build -t $(REPOPREFIX)/security-profiles-webhook:latest -f ./build/security-profiles-webhook/Dockerfile .

.PHONY: go-audit
go-audit:     ## Build go-audit docker
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/go-audit/cmd.Version=$(VERSION)" \
		-o dist/go-audit gitlab.com/piccolo_su/vegeta/cmd/go-audit
	docker build -t $(REPOPREFIX)/go-audit:latest -f ./build/go-audit/Dockerfile .

.PHONY: security-profiles-manager
security-profiles-manager:	## Build security-profiles-manager binary
	@echo "+ $@"
	cd cmd/security-profiles-manager; go generate; cd -
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/cmd.Version=$(VERSION)" \
		-o dist/security-profiles-manager gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager
	docker build -t $(REPOPREFIX)/security-profiles-manager:latest -f ./build/security-profiles-manager/Dockerfile .

.PHONY: security-profiles-loader-base
security-profiles-loader-base: ## Build security-profiles-loader base image
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	docker build -t $(REPOPREFIX)/baseimage-security-profiles-loader:latest \
    --build-arg MIRROR=mirrors.aliyun.com -f ./build/security-profiles-loader/baseimage-dockerfile .
else
	docker build -t $(REPOPREFIX)/baseimage-security-profiles-loader:latest \
    -f ./build/security-profiles-loader/baseimage-dockerfile .
endif

.PHONY: security-profiles-loader
security-profiles-loader:     ## Build security-profiles-loader docker
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/security-profiles-loader/cmd.Version=$(VERSION)" \
		-o dist/security-profiles-loader gitlab.com/piccolo_su/vegeta/cmd/security-profiles-loader
	docker build -t $(REPOPREFIX)/security-profiles-loader:latest -f ./build/security-profiles-loader/Dockerfile \
		--build-arg REPO=$(REPOPREFIX) .

.PHONY: holmes-base
holmes-base: ## Build holmes base image
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	docker build -t $(REPOPREFIX)/baseimage-holmes:latest \
    --build-arg MIRROR=mirrors.aliyun.com --build-arg REPO=$(REPOPREFIX) -f TAG=$(FETCHTAG) ./build/holmes/baseimage-dockerfile .
else
	docker build -t $(REPOPREFIX)/baseimage-holmes:latest \
    --build-arg REPO=$(REPOPREFIX) TAG=$(FETCHTAG) -f ./build/holmes/baseimage-dockerfile .
endif

.PHONY: holmes
holmes:     ## Build holmes docker
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/holmes/holmes-scheduler/cmd.Version=$(VERSION)" \
		-o dist/holmes-scheduler gitlab.com/piccolo_su/vegeta/cmd/holmes/holmes-scheduler
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/holmes/encodefile/cmd.Version=$(VERSION)" \
		-o dist/holmes-rules-pack gitlab.com/piccolo_su/vegeta/cmd/holmes/encodefile
	./dist/holmes-rules-pack --input configs/holmes/rules/holmes_rules.yaml --output ./dist/holmes-rules.thr
ifeq ($(USEMIRROR),true)
	@echo "holmes will use mirror"
	docker build -t $(REPOPREFIX)/holmes:latest -f ./build/holmes/Dockerfile \
                --build-arg MIRROR=mirrors.aliyun.com --build-arg REPO=$(REPOPREFIX) --build-arg TAG=$(FETCHTAG) .
else
	@echo "holmes will not use mirror"
	docker build -t $(REPOPREFIX)/holmes:latest -f ./build/holmes/Dockerfile --build-arg REPO=$(REPOPREFIX) TAG=$(FETCHTAG) .
endif

.PHONY: event-processor
event-processor:		## Build event-processor binary
	@echo "+ $@"
	# cat configs/holmes/rules/holmes_rules.yaml| shyaml get-value | grep "rule:\|priority:" > configs/holmes/rules/_rules_list.yaml
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/event-processor/cmd.Version=$(VERSION)" \
		-o dist/event-processor gitlab.com/piccolo_su/vegeta/cmd/event-processor
	docker build -t $(REPOPREFIX)/event-processor:latest -f ./build/event-processor/Dockerfile .

.PHONY: migrate
migrate: generate		## Build migrage binary
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS)" \
		-o dist/migrate gitlab.com/piccolo_su/vegeta/cmd/migrate

.PHONY: image-validate
image-validate: generate
	@echo "build image-validate"
	go build -v \
		-o dist/image-validator gitlab.com/piccolo_su/vegeta/cmd/image-validate
	docker build -t $(REPOPREFIX)/image-validator:latest -f ./build/image-validate/Dockerfile .


.PHONY: webhook
webhook: generate
	@echo "build webhook"
	go build -v \
		-o dist/webhook gitlab.com/piccolo_su/vegeta/cmd/webhook
	docker build -t $(REPOPREFIX)/webhook:latest -f ./build/webhook/Dockerfile .

.PHONY: cluster-manager
cluster-manager: generate
	@echo "build webhook"
	go build -v \
		-o dist/cluster-manager gitlab.com/piccolo_su/vegeta/cmd/cluster-manager
	docker build -t $(REPOPREFIX)/cluster-manager:latest -f ./build/cluster-manager/Dockerfile .

.PHONY: all
all: drift-prevention-client faulty scanner scanner-cicd scap-jobs console data holmes image-validate daemon  \
webshell-server webhook cluster-manager security-profiles-webhook security-profiles-manager security-profiles-loader \
event-processor go-audit safe-node-image kube-hunter-report platform-report

.PHONY: base
base: scanner-base host-bench-base faulty-base data-base drift-prevention-client-base holmes-base security-profiles-loader-base

.PHONY: deps
deps: alpine redis elasticsearch mongodb mongo-arbiter mongodb-init postgres-init postgres falcosidekick nats-streaming

.PHONY: pushdeps
pushdeps:
	docker push $(REPOPREFIX)/alpine:latest
	docker push $(REPOPREFIX)/redis:6.2.5-alpine
	docker push ${REPOPREFIX}/elasticsearch:7.9.1
	docker push ${REPOPREFIX}/bitnami-shell:10-debian-10-r91
	docker push $(REPOPREFIX)/minideb:buster
	docker push $(REPOPREFIX)/postgresql:11.6.0-debian-10-r5
	docker push $(REPOPREFIX)/falcosidekick:2.22.0
	docker push $(REPOPREFIX)/nats-streaming:0.21.2

.PHONY: pushbase
pushbase:
ifeq ($(USERELEASE),true)
	@echo "push all base images release"
	docker push $(REPOPREFIX)/baseimage-faulty:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/baseimage-holmes:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/baseimage-host-bench:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/baseimage-scanner:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/baseimage-drift-prevention-client:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/baseimage-data:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/baseimage-security-profiles-loader:$(RELEASEVERSION)
else
	@echo "push all base images latest"
	docker push $(REPOPREFIX)/baseimage-faulty:latest
	docker push $(REPOPREFIX)/baseimage-holmes:latest
	docker push $(REPOPREFIX)/baseimage-host-bench:latest
	docker push $(REPOPREFIX)/baseimage-scanner:latest
	docker push $(REPOPREFIX)/baseimage-drift-prevention-client:latest
	docker push $(REPOPREFIX)/baseimage-data:latest
	docker push $(REPOPREFIX)/baseimage-security-profiles-loader:latest
endif

.PHONY: pushimages
pushimages:
ifeq ($(USERELEASE),true)
	@echo "push all images release"
	docker push $(REPOPREFIX)/console:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/scanner:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/kube-bench:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/docker-bench-security:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/host-bench:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/cleaner:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/drift-prevention-client:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/faulty:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/security-profiles-webhook:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/security-profiles-manager:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/security-profiles-loader:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/event-processor:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/go-audit:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/holmes:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/daemon:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/image-validator:$(RELEASEVERSION)
	#docker push $(REPOPREFIX)/scarecrow:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/webshell-server:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/safe-node-image:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/webhook:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/cluster-manager:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/kube-hunter-report:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/platform-report:$(RELEASEVERSION)
else
	@echo "push all images latest"
	docker push $(REPOPREFIX)/console:latest
	docker push $(REPOPREFIX)/scanner:latest
	docker push $(REPOPREFIX)/kube-bench:latest
	docker push $(REPOPREFIX)/docker-bench-security:latest
	docker push $(REPOPREFIX)/host-bench:latest
	docker push $(REPOPREFIX)/cleaner:latest
	docker push $(REPOPREFIX)/drift-prevention-client:latest
	docker push $(REPOPREFIX)/faulty:latest
	docker push $(REPOPREFIX)/security-profiles-webhook:latest
	docker push $(REPOPREFIX)/security-profiles-manager:latest
	docker push $(REPOPREFIX)/security-profiles-loader:latest
	docker push $(REPOPREFIX)/event-processor:latest
	docker push $(REPOPREFIX)/go-audit:latest
	docker push $(REPOPREFIX)/holmes:latest
	docker push $(REPOPREFIX)/daemon:latest
	docker push $(REPOPREFIX)/image-validator:latest
	#docker push $(REPOPREFIX)/scarecrow:latest
	docker push $(REPOPREFIX)/webshell-server:latest
	docker push $(REPOPREFIX)/safe-node-image:latest
	docker push $(REPOPREFIX)/webhook:latest
	docker push $(REPOPREFIX)/cluster-manager:latest
	docker push $(REPOPREFIX)/kube-hunter-report:latest
	docker push $(REPOPREFIX)/platform-report:latest
endif

.PHONY: rm-local-images
rm-local-images:
	@echo "rm all local images latest"
	docker rmi $(REPOPREFIX)/console:latest
	docker rmi $(REPOPREFIX)/scanner:latest
	docker rmi $(REPOPREFIX)/kube-bench:latest
	docker rmi $(REPOPREFIX)/docker-bench-security:latest
	docker rmi $(REPOPREFIX)/host-bench:latest
	docker rmi $(REPOPREFIX)/cleaner:latest
	docker rmi $(REPOPREFIX)/drift-prevention-client:latest
	docker rmi $(REPOPREFIX)/faulty:latest
	docker rmi $(REPOPREFIX)/security-profiles-webhook:latest
	docker rmi $(REPOPREFIX)/security-profiles-manager:latest
	docker rmi $(REPOPREFIX)/security-profiles-loader:latest
	docker rmi $(REPOPREFIX)/event-processor:latest
	docker rmi $(REPOPREFIX)/go-audit:latest
	docker rmi $(REPOPREFIX)/holmes:latest
	docker rmi $(REPOPREFIX)/daemon:latest
	docker rmi $(REPOPREFIX)/image-validator:latest
	#docker rmi $(REPOPREFIX)/scarecrow:latest
	docker rmi $(REPOPREFIX)/webshell-server:latest
	docker rmi $(REPOPREFIX)/safe-node-image:latest
	docker rmi $(REPOPREFIX)/webhook:latest
	docker rmi $(REPOPREFIX)/cluster-manager:latest
	docker rmi $(REPOPREFIX)/kube-hunter-report:latest

.PHONY: retag
retag:
ifeq ($(USERELEASE),true)
	@echo "tag all images release"
	docker tag $(REPOPREFIX)/console:latest $(REPOPREFIX)/console:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/scanner:latest $(REPOPREFIX)/scanner:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/kube-bench:latest $(REPOPREFIX)/kube-bench:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/docker-bench-security:latest $(REPOPREFIX)/docker-bench-security:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/host-bench:latest $(REPOPREFIX)/host-bench:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/cleaner:latest $(REPOPREFIX)/cleaner:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/drift-prevention-client:latest $(REPOPREFIX)/drift-prevention-client:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/faulty:latest $(REPOPREFIX)/faulty:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/security-profiles-webhook:latest $(REPOPREFIX)/security-profiles-webhook:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/security-profiles-manager:latest $(REPOPREFIX)/security-profiles-manager:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/security-profiles-loader:latest $(REPOPREFIX)/security-profiles-loader:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/event-processor:latest $(REPOPREFIX)/event-processor:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/go-audit:latest $(REPOPREFIX)/go-audit:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/holmes:latest $(REPOPREFIX)/holmes:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/daemon:latest $(REPOPREFIX)/daemon:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/image-validator:latest $(REPOPREFIX)/image-validator:$(RELEASEVERSION)
	#docker tag $(REPOPREFIX)/scarecrow:latest $(REPOPREFIX)/scarecrow:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/webshell-server:latest $(REPOPREFIX)/webshell-server:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/safe-node-image:latest $(REPOPREFIX)/safe-node-image:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/webhook:latest $(REPOPREFIX)/webhook:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/cluster-manager:latest $(REPOPREFIX)/cluster-manager:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/kube-hunter-report:latest $(REPOPREFIX)/kube-hunter-report:$(RELEASEVERSION)
else
	@echo "tag all images latest"
	docker tag $(REPOPREFIXOLD)/console:latest $(REPOPREFIX)/console:latest
	docker tag $(REPOPREFIXOLD)/scanner:latest $(REPOPREFIX)/scanner:latest
	docker tag $(REPOPREFIXOLD)/kube-bench:latest $(REPOPREFIX)/kube-bench:latest
	docker tag $(REPOPREFIXOLD)/docker-bench-security:latest $(REPOPREFIX)/docker-bench-security:latest
	docker tag $(REPOPREFIXOLD)/host-bench:latest $(REPOPREFIX)/host-bench:latest
	docker tag $(REPOPREFIXOLD)/cleaner:latest $(REPOPREFIX)/cleaner:latest
	docker tag $(REPOPREFIXOLD)/drift-prevention-client:latest $(REPOPREFIX)/drift-prevention-client:latest
	docker tag $(REPOPREFIXOLD)/faulty:latest $(REPOPREFIX)/faulty:latest
	docker tag $(REPOPREFIXOLD)/security-profiles-webhook:latest $(REPOPREFIX)/security-profiles-webhook:latest
	docker tag $(REPOPREFIXOLD)/security-profiles-manager:latest $(REPOPREFIX)/security-profiles-manager:latest
	docker tag $(REPOPREFIXOLD)/security-profiles-loader:latest $(REPOPREFIX)/security-profiles-loader:latest
	docker tag $(REPOPREFIXOLD)/event-processor:latest $(REPOPREFIX)/event-processor:latest
	docker tag $(REPOPREFIXOLD)/go-audit:latest $(REPOPREFIX)/go-audit:latest
	docker tag $(REPOPREFIXOLD)/holmes:latest $(REPOPREFIX)/holmes:latest
	docker tag $(REPOPREFIXOLD)/daemon:latest $(REPOPREFIX)/daemon:latest
	docker tag $(REPOPREFIXOLD)/image-validator:latest $(REPOPREFIX)/image-validator:latest
	#docker tag $(REPOPREFIXOLD)/scarecrow:latest $(REPOPREFIX)/scarecrow:latest
	docker tag $(REPOPREFIXOLD)/webshell-server:latest $(REPOPREFIX)/webshell-server:latest
	docker tag $(REPOPREFIXOLD)/safe-node-image:latest $(REPOPREFIX)/safe-node-image:latest
	docker tag $(REPOPREFIXOLD)/webhook:latest $(REPOPREFIX)/webhook:latest
	docker tag $(REPOPREFIXOLD)/cluster-manager:latest $(REPOPREFIX)/cluster-manager:latest
	docker tag $(REPOPREFIXOLD)/kube-hunter-report:latest $(REPOPREFIX)/kube-hunter-report:latest
endif

CI_CHECK_CACHE_REGISTRY?=harbor.local.cn
CI_CHECK_CONSOLE?=https://console.local.cn

.PHONY: ci-check-images
ci-check-images:
ifeq ($(USERELEASE),true)
	@echo "ci check all images release"
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/console:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/scanner:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/kube-bench:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/docker-bench-security:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/host-bench:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/cleaner:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/drift-prevention-client:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/faulty:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/security-profiles-webhook:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/security-profiles-manager:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/security-profiles-loader:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/event-processor:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/go-audit:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/holmes:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/daemon:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/image-validator:$(RELEASEVERSION)
	#tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/scarecrow:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/webshell-server:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/safe-node-image:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/webhook:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/cluster-manager:$(RELEASEVERSION)
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/kube-hunter-report:$(RELEASEVERSION)
else
	@echo "ci check all images latest"
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/console:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/scanner:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/kube-bench:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/docker-bench-security:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/host-bench:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/cleaner:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/drift-prevention-client:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/faulty:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/security-profiles-webhook:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/security-profiles-manager:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/security-profiles-loader:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/event-processor:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/go-audit:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/holmes:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/daemon:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/image-validator:latest
	#tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/scarecrow:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/webshell-server:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/safe-node-image:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/webhook:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/cluster-manager:latest
	tensor-scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/kube-hunter-report:latest
endif
