VERSION = 0.1.0

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDFLAGS = '-extldflags "-static"'
endif

REPOPREFIX?=localhost:32000
REPOPREFIXOLD?=localhost:32000

USEMIRROR?=false

RELEASEVERSION?=v0.0.1

FETCHTAG?=latest

LICENSE_SECRET?=sit

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

.PHONY: console
console: generate 		## Build console binary
	# This target depends on scap-jobs, but for optimisation, if we want to build only console, they won't be built.
	# To build all targets, use make all.
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/console/cmd.Version=$(VERSION)" \
		-tags $(LICENSE_SECRET) -o dist/console gitlab.com/piccolo_su/vegeta/cmd/console
	#upx dist/console

	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/holmes/encodefile/cmd.Version=$(VERSION)" \
		-o dist/holmes-rules-pack gitlab.com/piccolo_su/vegeta/cmd/holmes/encodefile
	#upx dist/holmes-rules-pack
	# generate the holmes rules thr file with version
	./build_holmes_rules_thr.sh

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
	#upx dist/cleaner
	docker build -t $(REPOPREFIX)/cleaner:latest --build-arg REPO=$(REPOPREFIX) -f ./build/data/Dockerfile  --build-arg MIRROR=mirrors.aliyun.com .

.PHONY: kube-scanner-report
kube-scanner-report: generate
	@echo "+ $@"
	CGO_ENABLED=0 go build -v \
    		-o dist/kube-scanner-report gitlab.com/piccolo_su/vegeta/cmd/kube-scanner-report
	#upx dist/kube-scanner-report
	docker build -t $(REPOPREFIX)/kube-scanner-report:latest --build-arg REPO=$(REPOPREFIX) -f ./build/kube-scanner-report/Dockerfile .

.PHONY: platform-report
platform-report: generate
	@echo "+ $@"
	CGO_ENABLED=0 go build -v \
    		-o dist/platform-report gitlab.com/piccolo_su/vegeta/cmd/platform-report
	#upx dist/platform-report
	docker build -t $(REPOPREFIX)/platform-report:latest --build-arg REPO=$(REPOPREFIX) -f ./build/platform-report/Dockerfile .

.PHONY: immune-test
immune-test: generate
	@echo "+ $@"
	mkdir -p dist
	echo "initial" > dist/immune-test-1.txt
	echo "initial" > dist/immune-test-2.txt
	chmod 777 dist/immune-test-1.txt
	chmod 777 dist/immune-test-2.txt
	CGO_ENABLED=0 go build -v \
    		-o dist/immune-test gitlab.com/piccolo_su/vegeta/cmd/immune-test
	#upx dist/immune-test
	docker build -t $(REPOPREFIX)/immune-test:latest --build-arg REPO=$(REPOPREFIX) -f ./build/immune-test/Dockerfile .


.PHONY: scanner-base
scanner-base: ## Build scanner base image
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	docker build -t $(REPOPREFIX)/baseimage-scanner:latest --build-arg TAG=$(FETCHTAG) \
    --build-arg REPO=$(REPOPREFIX) --build-arg MIRROR=mirrors.aliyun.com -f ./build/scanner/baseimage-dockerfile .
else
	docker build -t $(REPOPREFIX)/baseimage-scanner:latest --build-arg TAG=$(FETCHTAG) \
    --build-arg REPO=$(REPOPREFIX) -f ./build/scanner/baseimage-dockerfile .
endif

.PHONY: webshell-server
webshell-server: 		## Build cleaner binary
	@echo "+ $@"
	CGO_ENABLED=1 CGO_LDFLAGS=-no-pie go build -v \
		-o dist/webshell-server cmd/webshell-server/cmd/main.go
	#upx dist/webshell-server
	docker build -t $(REPOPREFIX)/webshell-server:latest -f ./build/webshell-server/Dockerfile .

.PHONY: scanner-cicd
scanner-cicd: generate
	echo "+ $@"
	go build -v \
                --ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd/cmd.Version=$(VERSION)" \
                -o dist/scanner-cicd gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd
	#upx dist/scanner-cicd

.PHONY: safe-node-image
safe-node-image: generate
	echo "+ $@"
	go build -v  -o dist/safe-node-image  cmd/scripts/safe-node-image/main.go
	#upx dist/safe-node-image
	docker build -t $(REPOPREFIX)/safe-node-image:latest -f ./build/safe-node-image/Dockerfile .

.PHONY: scanner
scanner: generate		## Build scanner binary
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd.Version=$(VERSION)" \
		-o dist/scanner gitlab.com/piccolo_su/vegeta/cmd/scanner
	#upx dist/scanner
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
daemon: drift-prevention-client ## Build daemon binary
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "daemon will use mirror"
	go build -v -o bin/daemon  cmd/daemon/main.go
	gcc -o bin/ns-mnt  cmd/daemon/setns/*.c
	#upx bin/daemon
	#upx bin/ns-mnt
	docker build -f build/daemon/Dockerfile -t $(REPOPREFIX)/daemon:latest \
        --build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
else
	@echo "daemon will not use mirror"
	go build -v -o bin/daemon  cmd/daemon/main.go
	gcc -o bin/ns-mnt  cmd/daemon/setns/*.c
	#upx bin/daemon
	docker build -f build/daemon/Dockerfile -t $(REPOPREFIX)/daemon:latest .
endif


.PHONY: scarecrow
scarecrow:   ## Build scarecrow docker to test CVEs
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "scarecrow will use mirror"
	docker build -t $(REPOPREFIX)/waston-redis:latest -f ./build/scarecrow/Dockerfile \
		--build-arg MIRROR=mirrors.aliyun.com --build-arg TAG=$(RELEASEVERSION) .
else
	@echo "scarecrow will not use mirror"
	docker build -t $(REPOPREFIX)/waston-redis:latest -f ./build/scarecrow/Dockerfile \
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

.PHONY: drift-prevention-client
drift-prevention-client:	## Build drift prevention client binary
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	(cd configs/drift-prevention && ./run.sh mirrors.aliyun.com)
else
	@echo "drift-prevention-client will not use mirror"
	(cd configs/drift-prevention && ./run.sh)
endif

.PHONY: go-audit
go-audit:     ## Build go-audit docker
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/go-audit/cmd.Version=$(VERSION)" \
		-o dist/go-audit gitlab.com/piccolo_su/vegeta/cmd/go-audit
	#upx dist/go-audit
	docker build -t $(REPOPREFIX)/go-audit:latest -f ./build/go-audit/Dockerfile .

.PHONY: security-profiles-manager
security-profiles-manager:	## Build security-profiles-manager binary
	@echo "+ $@"
	cd cmd/security-profiles-manager; go generate; cd -
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/cmd.Version=$(VERSION)" \
		-o dist/security-profiles-manager gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager
	#upx dist/security-profiles-manager
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
	#upx dist/security-profiles-loader
	docker build -t $(REPOPREFIX)/security-profiles-loader:latest -f ./build/security-profiles-loader/Dockerfile \
		--build-arg REPO=$(REPOPREFIX) .

.PHONY: holmes-base
holmes-base: ## Build holmes base image
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	docker build -t $(REPOPREFIX)/baseimage-holmes:latest \
    --build-arg MIRROR=mirrors.aliyun.com --build-arg REPO=$(REPOPREFIX) --build-arg TAG=$(FETCHTAG) -f  ./build/holmes/baseimage-dockerfile .
else
	docker build -t $(REPOPREFIX)/baseimage-holmes:latest \
    --build-arg REPO=$(REPOPREFIX) --build-arg TAG=$(FETCHTAG) -f ./build/holmes/baseimage-dockerfile .
endif

.PHONY: holmes
holmes:     ## Build holmes docker
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/holmes/holmesscheduler/cmd.Version=$(VERSION)" \
		-o dist/holmes-scheduler gitlab.com/piccolo_su/vegeta/cmd/holmes/holmesscheduler
	#upx dist/holmes-scheduler
	# go build -v \
	# 	--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/holmes/enginesider/cmd.Version=$(VERSION)" \
	# 	-o dist/holmes-engine-sider gitlab.com/piccolo_su/vegeta/cmd/holmes/enginesider
	# #upx dist/holmes-engine-sider
	rm -rf ./dist/*.thr > /dev/null 2>&1
	sync

	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/holmes/encodefile/cmd.Version=$(VERSION)" \
		-o dist/holmes-rules-pack gitlab.com/piccolo_su/vegeta/cmd/holmes/encodefile
	#upx dist/holmes-rules-pack
	# generate the holmes rules thr file with version
	./build_holmes_rules_thr.sh
ifeq ($(USEMIRROR),true)
	@echo "holmes will use mirror"
	docker build -t $(REPOPREFIX)/holmes:latest -f ./build/holmes/Dockerfile \
                --build-arg MIRROR=mirrors.aliyun.com --build-arg REPO=$(REPOPREFIX) --build-arg TAG=$(FETCHTAG) .
else
	@echo "holmes will not use mirror"
	docker build -t $(REPOPREFIX)/holmes:latest -f ./build/holmes/Dockerfile --build-arg REPO=$(REPOPREFIX) TAG=$(FETCHTAG) .
endif

.PHONY: palace
palace:		## Build palace binary
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/palace/cmd.Version=$(VERSION)" \
		-o dist/palace gitlab.com/piccolo_su/vegeta/cmd/palace
	#upx dist/palace
	docker build -t $(REPOPREFIX)/palace:latest -f ./build/palace/Dockerfile .

.PHONY: migrate
migrate: generate		## Build migrage binary
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS)" \
		-o dist/migrate gitlab.com/piccolo_su/vegeta/cmd/migrate
	#upx dist/migrate

.PHONY: image-validate
image-validate: generate
	@echo "build image-validate"
	go build -v \
		-o dist/image-validator gitlab.com/piccolo_su/vegeta/cmd/image-validate
	#upx dist/image-validator
	docker build -t $(REPOPREFIX)/image-validator:latest -f ./build/image-validate/Dockerfile .

.PHONY: webhook
webhook: generate
	@echo "build webhook"
	go build -v \
		-o dist/webhook gitlab.com/piccolo_su/vegeta/cmd/webhook
	#upx dist/webhook
	docker build -t $(REPOPREFIX)/webhook:latest -f ./build/webhook/Dockerfile .

.PHONY: cluster-manager
cluster-manager: generate
	@echo "build webhook"
	go build -v \
		-o dist/cluster-manager gitlab.com/piccolo_su/vegeta/cmd/clustermanager
	#upx dist/cluster-manager
	docker build -t $(REPOPREFIX)/cluster-manager:latest -f ./build/cluster-manager/Dockerfile .

.PHONY: scan_report
scan_report: 		## Build cleaner binary
	@echo "+ $@"
	GOOS=linux GOARCH=amd64 go build -trimpath -v \
		-o dist/scan_report cmd/scanner/bin/scan-report/main.go
	#upx dist/scan_report
	docker build -t $(REPOPREFIX)/scan-report:latest -f ./build/scan_report/Dockerfile .

.PHONY: apiscan-job
apiscan-job: generate
	@echo "build apiscan-job"
	go build -v \
		-o dist/apiscan gitlab.com/piccolo_su/vegeta/cmd/apiscan-job
	#upx dist/apiscan
	docker build -t $(REPOPREFIX)/apiscan-job:latest -f ./build/apiscan-job/Dockerfile .

.PHONY: all
all: drift-prevention-client faulty scanner scanner-cicd scarecrow console data holmes daemon  \
webshell-server webhook cluster-manager palace safe-node-image kube-scanner-report platform-report \
scan_report apiscan-job

.PHONY: base
base: scanner-base faulty-base data-base drift-prevention-client-base holmes-base security-profiles-loader-base

.PHONY: deps
deps: alpine redis elasticsearch mongodb mongo-arbiter mongodb-init postgres-init postgres nats-streaming

.PHONY: pushdeps
pushdeps:
	docker push $(REPOPREFIX)/alpine:latest
	docker push $(REPOPREFIX)/redis:6.2.5-alpine
	docker push ${REPOPREFIX}/elasticsearch:7.9.1
	docker push ${REPOPREFIX}/bitnami-shell:10-debian-10-r91
	docker push $(REPOPREFIX)/minideb:buster
	docker push $(REPOPREFIX)/postgresql:11.6.0-debian-10-r5
	docker push $(REPOPREFIX)/nats-streaming:0.21.2

.PHONY: pushbase
pushbase:
ifeq ($(USERELEASE),true)
	@echo "push all base images release"
	docker push $(REPOPREFIX)/baseimage-faulty:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/baseimage-holmes:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/baseimage-scanner:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/baseimage-data:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/baseimage-security-profiles-loader:$(RELEASEVERSION)
else
	@echo "push all base images latest"
	docker push $(REPOPREFIX)/baseimage-faulty:latest
	docker push $(REPOPREFIX)/baseimage-holmes:latest
	docker push $(REPOPREFIX)/baseimage-scanner:latest
	docker push $(REPOPREFIX)/baseimage-data:latest
	docker push $(REPOPREFIX)/baseimage-security-profiles-loader:latest
endif

.PHONY: pushimages
pushimages:
ifeq ($(USERELEASE),true)
	@echo "push all images release"
	docker push $(REPOPREFIX)/console:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/scanner:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/cleaner:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/faulty:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/palace:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/holmes:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/daemon:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/waston-redis:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/webshell-server:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/safe-node-image:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/webhook:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/cluster-manager:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/kube-scanner-report:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/platform-report:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/scan-report:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/apiscan-job:$(RELEASEVERSION)
else
	@echo "push all images latest"
	docker push $(REPOPREFIX)/console:latest
	docker push $(REPOPREFIX)/scanner:latest
	docker push $(REPOPREFIX)/cleaner:latest
	docker push $(REPOPREFIX)/faulty:latest
	docker push $(REPOPREFIX)/palace:latest
	docker push $(REPOPREFIX)/holmes:latest
	docker push $(REPOPREFIX)/daemon:latest
	docker push $(REPOPREFIX)/waston-redis:latest
	docker push $(REPOPREFIX)/webshell-server:latest
	docker push $(REPOPREFIX)/safe-node-image:latest
	docker push $(REPOPREFIX)/webhook:latest
	docker push $(REPOPREFIX)/cluster-manager:latest
	docker push $(REPOPREFIX)/kube-scanner-report:latest
	docker push $(REPOPREFIX)/platform-report:latest
	docker push $(REPOPREFIX)/scan-report:latest
	docker push $(REPOPREFIX)/apiscan-job:latest
endif

.PHONY: rm-local-images
rm-local-images:
	@echo "rm all local images latest"
	docker rmi $(REPOPREFIX)/console:latest
	docker rmi $(REPOPREFIX)/scanner:latest
	docker rmi $(REPOPREFIX)/cleaner:latest
	docker rmi $(REPOPREFIX)/faulty:latest
	docker rmi $(REPOPREFIX)/palace:latest
	docker rmi $(REPOPREFIX)/holmes:latest
	docker rmi $(REPOPREFIX)/daemon:latest
	docker rmi $(REPOPREFIX)/waston-redis:latest
	docker rmi $(REPOPREFIX)/webshell-server:latest
	docker rmi $(REPOPREFIX)/safe-node-image:latest
	docker rmi $(REPOPREFIX)/webhook:latest
	docker rmi $(REPOPREFIX)/cluster-manager:latest
	docker rmi $(REPOPREFIX)/kube-scanner-report:latest
	docker rmi $(REPOPREFIX)/scan-report:latest
	docker rmi $(REPOPREFIX)/apiscan-job:latest
	docker rmi $(REPOPREFIX)/platform-report:latest

.PHONY: retag
retag:
ifeq ($(USERELEASE),true)
	@echo "tag all images release"
	docker tag $(REPOPREFIX)/console:latest $(REPOPREFIX)/console:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/scanner:latest $(REPOPREFIX)/scanner:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/cleaner:latest $(REPOPREFIX)/cleaner:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/faulty:latest $(REPOPREFIX)/faulty:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/palace:latest $(REPOPREFIX)/palace:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/holmes:latest $(REPOPREFIX)/holmes:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/daemon:latest $(REPOPREFIX)/daemon:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/image-validator:latest $(REPOPREFIX)/image-validator:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/waston-redis:latest $(REPOPREFIX)/waston-redis:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/webshell-server:latest $(REPOPREFIX)/webshell-server:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/safe-node-image:latest $(REPOPREFIX)/safe-node-image:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/webhook:latest $(REPOPREFIX)/webhook:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/cluster-manager:latest $(REPOPREFIX)/cluster-manager:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/kube-scanner-report:latest $(REPOPREFIX)/kube-scanner-report:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/apiscan-job:latest $(REPOPREFIX)/apiscan-job:$(RELEASEVERSION)
else
	@echo "tag all images latest"
	docker tag $(REPOPREFIXOLD)/console:latest $(REPOPREFIX)/console:latest
	docker tag $(REPOPREFIXOLD)/scanner:latest $(REPOPREFIX)/scanner:latest
	docker tag $(REPOPREFIXOLD)/cleaner:latest $(REPOPREFIX)/cleaner:latest
	docker tag $(REPOPREFIXOLD)/faulty:latest $(REPOPREFIX)/faulty:latest
	docker tag $(REPOPREFIXOLD)/palace:latest $(REPOPREFIX)/palace:latest
	docker tag $(REPOPREFIXOLD)/holmes:latest $(REPOPREFIX)/holmes:latest
	docker tag $(REPOPREFIXOLD)/daemon:latest $(REPOPREFIX)/daemon:latest
	docker tag $(REPOPREFIXOLD)/image-validator:latest $(REPOPREFIX)/image-validator:latest
	docker tag $(REPOPREFIXOLD)/waston-redis:latest $(REPOPREFIX)/waston-redis:latest
	docker tag $(REPOPREFIXOLD)/webshell-server:latest $(REPOPREFIX)/webshell-server:latest
	docker tag $(REPOPREFIXOLD)/safe-node-image:latest $(REPOPREFIX)/safe-node-image:latest
	docker tag $(REPOPREFIXOLD)/webhook:latest $(REPOPREFIX)/webhook:latest
	docker tag $(REPOPREFIXOLD)/cluster-manager:latest $(REPOPREFIX)/cluster-manager:latest
	docker tag $(REPOPREFIXOLD)/kube-scanner-report:latest $(REPOPREFIX)/kube-scanner-report:latest
	docker tag $(REPOPREFIXOLD)/apiscan-job:latest $(REPOPREFIX)/apiscan-job:latest
endif

CI_CHECK_CACHE_REGISTRY?=harbor.local.cn
CI_CHECK_CONSOLE?=https://console.local.cn

.PHONY: ci-check-images
ci-check-images:
ifeq ($(USERELEASE),true)
	@echo "ci check all images release"
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/console:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/scanner:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/cleaner:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/faulty:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/palace:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/holmes:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/daemon:$(RELEASEVERSION)
	#scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/scarecrow:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/webshell-server:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/safe-node-image:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/webhook:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/cluster-manager:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/kube-scanner-report:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/platform-report:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/scan-report:$(RELEASEVERSION)
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/apiscan-job:$(RELEASEVERSION)
else
	@echo "ci check all images latest"
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/console:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/scanner:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/cleaner:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/faulty:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/palace:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/holmes:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/daemon:latest
	#scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/scarecrow:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/webshell-server:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/safe-node-image:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/webhook:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/cluster-manager:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/kube-scanner-report:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/platform-report:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/scan-report:latest
	scanner-cicd -k=dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv -c=$(CI_CHECK_CONSOLE) -r=$(CI_CHECK_CACHE_REGISTRY) -t=1000 --insecure=false -i=$(REPOPREFIX)/apiscan-job:latest
endif
