VERSION = 0.1.0

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDFLAGS = '-extldflags "-static"'
endif

REPOPREFIX?=localhost:32000
REPOPREFIXOLD?=localhost:32000

USEMIRROR?=definitelynottrue

RELEASEVERSION?=v0.0.1

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
	# go get -u sigs.k8s.io/controller-tools/cmd/controller-gen
	# cd cmd/seccomp-generator; controller-gen object paths=./api/types/v1/seccompProfile.go; cd -

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
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "scap-jobs will use mirror"
	cd configs/scap/jobs/kube-bench && \
		docker build -t $(REPOPREFIX)/kube-bench:latest \
			--build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
	cd configs/scap/jobs/docker-bench-security && \
		docker build -t $(REPOPREFIX)/docker-bench-security:latest \
			--build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
	cd configs/scap/jobs/host-bench && \
		docker build -t $(REPOPREFIX)/host-bench:latest \
			--build-arg MIRROR=mirrors.aliyun.com .
else
	@echo "scap-jobs will not use mirror"
	cd configs/scap/jobs/kube-bench && \
		$(MAKE) DOCKER_REGISTRY=$(REPOPREFIX)/ VERSION=latest build-docker
	cd configs/scap/jobs/docker-bench-security && \
		docker build -t $(REPOPREFIX)/docker-bench-security:latest .
	cd configs/scap/jobs/host-bench && \
		docker build -t $(REPOPREFIX)/host-bench:latest .
endif

.PHONY: console
console: generate 		## Build console binary
	# This target depends on scap-jobs, but for optimisation, if we want to build only console, they won't be built.
	# To build all targets, use make all.
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/console/cmd.Version=$(VERSION)" \
		-o dist/tensor-console gitlab.com/piccolo_su/vegeta/cmd/console
	docker build -t $(REPOPREFIX)/tensorsec-console:latest -f ./build/console/Dockerfile .

.PHONY: data
data: generate 		## Build cleaner binary
	@echo "+ $@"
	CGO_ENABLED=0 go build -v \
		-o dist/tensor-cleaner gitlab.com/piccolo_su/vegeta/cmd/data/tool/main
	docker build -t $(REPOPREFIX)/tensorsec-cleaner:latest -f ./build/data/Dockerfile  --build-arg MIRROR=mirrors.aliyun.com .

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
                -o dist/tensor-scanner-cicd gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd

.PHONY: scanner
scanner: generate		## Build scanner binary
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd.Version=$(VERSION)" \
		-o dist/tensor-scanner gitlab.com/piccolo_su/vegeta/cmd/scanner
	docker build -t $(REPOPREFIX)/tensorsec-scanner:latest -f ./build/scanner/Dockerfile .

.PHONY: tensordig
tensordig: ## Build tensordig binary
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "tensordig will use mirror"
	docker build -t $(REPOPREFIX)/tensordig:latest  -f ./build/tensordig/Dockerfile \
		--build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
else
	@echo "tensordig will not use mirror"
	docker build -t $(REPOPREFIX)/tensordig:latest  -f ./build/tensordig/Dockerfile .
endif

.PHONY: daemon
daemon: ## Build daemon binary
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "daemon will use mirror"
	go build -v -o bin/tensorsec-daemon  cmd/daemon/main.go
	docker build -f build/daemon/Dockerfile -t $(REPOPREFIX)/tensorsec-daemon:latest \
        --build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
else
	@echo "daemon will use mirror"
	go build -v -o bin/tensorsec-daemon  cmd/daemon/main.go
	docker build -f build/daemon/Dockerfile -t $(REPOPREFIX)/tensorsec-daemon:latest .
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
		--build-arg MIRROR=mirrors.aliyun.com --build-arg TAG=$(RELEASEVERSION) .
else
	@echo "faulty will not use mirror"
	docker build -t $(REPOPREFIX)/faulty:latest -f ./build/faulty/Dockerfile \
		--build-arg TAG=$(RELEASEVERSION) .
endif

.PHONY: drift-prevention-client
drift-prevention-client:	## Build drift prevention client binary
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	(cd configs/drift-prevention && ./run.sh mirrors.aliyun.com)
	go build -v -a -o dist/file-checker cmd/file-checker/main.go
	@echo "drift-prevention-client will use mirror"
	docker build -t $(REPOPREFIX)/tensorsec-drift-prevention-client:latest -f ./build/drift-prevention-client/Dockerfile \
		--build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
	docker tag $(REPOPREFIX)/tensorsec-drift-prevention-client:latest $(REPOPREFIX)/tensorsec-drift-prevention-client:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-drift-prevention-client:$(RELEASEVERSION)
else
	@echo "drift-prevention-client will not use mirror"
	(cd configs/drift-prevention && ./run.sh)
	go build -v -a -o dist/file-checker cmd/file-checker/main.go
	docker build -t $(REPOPREFIX)/tensorsec-drift-prevention-client:latest -f ./build/drift-prevention-client/Dockerfile .
	docker tag $(REPOPREFIX)/tensorsec-drift-prevention-client:latest $(REPOPREFIX)/tensorsec-drift-prevention-client:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-drift-prevention-client:$(RELEASEVERSION)
endif

.PHONY: drift-prevention
drift-prevention:     ## Build drift-prevention docker
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "drift-prevention will use mirror"
	docker build -t $(REPOPREFIX)/tensorsec-drift-prevention:latest -f ./build/drift-prevention/Dockerfile \
		--build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
else
	@echo "drift-prevention will not use mirror"
	docker build -t $(REPOPREFIX)/tensorsec-drift-prevention:latest -f ./build/drift-prevention/Dockerfile .
endif

.PHONY: seccomp-generator
seccomp-generator: generate	## Build seccomp-generator docker
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/seccomp-generator/cmd.Version=$(VERSION)" \
		-o dist/vegeta-seccomp-generator gitlab.com/piccolo_su/vegeta/cmd/seccomp-generator
	docker build -t $(REPOPREFIX)/tensorsec-seccomp-generator:latest -f ./build/seccomp-generator/Dockerfile .

.PHONY: seccomp-generator-webhook
seccomp-generator-webhook:     ## Build seccomp-generator-webhook docker
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "seccomp-generator-webhook will use mirror"
	docker build -t $(REPOPREFIX)/tensorsec-seccomp-generator-webhook:latest -f ./build/seccomp-generator-webhook/Dockerfile \
		--build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
else
	@echo "seccomp-generator-webhook will not use mirror"
	docker build -t $(REPOPREFIX)/tensorsec-seccomp-generator-webhook:latest -f ./build/seccomp-generator-webhook/Dockerfile .
endif

.PHONY: go-audit
go-audit:     ## Build go-audit docker
	@echo "+ $@"
ifeq ($(USEMIRROR),true)
	@echo "go-audit will use mirror"
	docker build -t $(REPOPREFIX)/tensorsec-go-audit:latest -f ./build/go-audit/Dockerfile \
		--build-arg GOPROXY=https://goproxy.cn --build-arg MIRROR=mirrors.aliyun.com .
else
	@echo "go-audit will not use mirror"
	docker build -t $(REPOPREFIX)/tensorsec-go-audit:latest -f ./build/go-audit/Dockerfile .
endif

.PHONY: holmes
holmes:     ## Build holmes docker
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/holmes/update/cmd.Version=$(VERSION)" \
		-o dist/holmes-rules-update gitlab.com/piccolo_su/vegeta/cmd/holmes/update
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/holmes/encodefile/cmd.Version=$(VERSION)" \
		-o dist/holmes-rules-pack gitlab.com/piccolo_su/vegeta/cmd/holmes/encodefile
	./dist/holmes-rules-pack --input configs/holmes/rules/holmes_rules.yaml --output ./dist/tensorsec-holmes-rules.thr
ifeq ($(USEMIRROR),true)
	@echo "holmes will use mirror"
	docker build -t $(REPOPREFIX)/tensorsec-holmes:latest -f ./build/holmes/Dockerfile \
                --build-arg MIRROR=mirrors.aliyun.com .
else
	@echo "holmes will not use mirror"
	docker build -t $(REPOPREFIX)/tensorsec-holmes:latest -f ./build/holmes/Dockerfile .
endif

.PHONY: migrate
migrate: generate		## Build scanner binary
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS)" \
		-o dist/tensor-migrate gitlab.com/piccolo_su/vegeta/cmd/migrate

.PHONY: image-validate
image-validate: generate
	@echo "build image-validate"
	go build -v \
		-o dist/image-validator gitlab.com/piccolo_su/vegeta/cmd/image-validate
	docker build -t $(REPOPREFIX)/tensorsec-image-validator:latest -f ./build/image-validate/Dockerfile .

.PHONY: webhook
webhook: generate
	@echo "build webhook"
	go build -v \
		-o dist/webhook gitlab.com/piccolo_su/vegeta/cmd/webhook
	docker build -t $(REPOPREFIX)/tensorsec-webhook:latest -f ./build/webhook/Dockerfile .

.PHONY: cluster-manager
cluster-manager: generate
	@echo "build webhook"
	go build -v \
		-o dist/cluster-manager gitlab.com/piccolo_su/vegeta/cmd/cluster-manager
	docker build -t $(REPOPREFIX)/tensorsec-cluster-manager:latest -f ./build/cluster-manager/Dockerfile .

.PHONY: all
all: drift-prevention-client faulty scanner scanner-cicd scap-jobs console data drift-prevention holmes image-validate daemon webshell-server webhook cluster-manager
	@echo "USEMIRROR is true by default. REVERT ME."

.PHONY: pushimages
pushimages:
ifeq ($(USERELEASE),true)
	@echo "push all images release"
	docker push $(REPOPREFIX)/tensorsec-console:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-scanner:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/kube-bench:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/docker-bench-security:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/host-bench:$(RELEASEVERSION)
	#docker push $(REPOPREFIX)/tensordig:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-cleaner:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-drift-prevention:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-drift-prevention-client:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/faulty:$(RELEASEVERSION)
	#docker push $(REPOPREFIX)/tensorsec-seccomp-generator:$(RELEASEVERSION)
	#docker push $(REPOPREFIX)/tensorsec-seccomp-generator-webhook:$(RELEASEVERSION)
	# docker push $(REPOPREFIX)/tensorsec-go-audit:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-holmes:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-daemon:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-image-validator:$(RELEASEVERSION)
	#docker push $(REPOPREFIX)/scarecrow:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/webshell-server:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-webhook:$(RELEASEVERSION)
	docker push $(REPOPREFIX)/tensorsec-cluster-manager:$(RELEASEVERSION)
else
	@echo "push all images latest"
	docker push $(REPOPREFIX)/tensorsec-console:latest
	docker push $(REPOPREFIX)/tensorsec-scanner:latest
	docker push $(REPOPREFIX)/kube-bench:latest
	docker push $(REPOPREFIX)/docker-bench-security:latest
	docker push $(REPOPREFIX)/host-bench:latest
	#docker push $(REPOPREFIX)/tensordig:latest
	docker push $(REPOPREFIX)/tensorsec-cleaner:latest
	docker push $(REPOPREFIX)/tensorsec-drift-prevention:latest
	docker push $(REPOPREFIX)/tensorsec-drift-prevention-client:latest
	docker push $(REPOPREFIX)/faulty:latest
	#docker push $(REPOPREFIX)/tensorsec-seccomp-generator:latest
	#docker push $(REPOPREFIX)/tensorsec-seccomp-generator-webhook:latest
	# docker push $(REPOPREFIX)/tensorsec-go-audit:latest
	docker push $(REPOPREFIX)/tensorsec-holmes:latest
	docker push $(REPOPREFIX)/tensorsec-daemon:latest
	docker push $(REPOPREFIX)/tensorsec-image-validator:latest
	#docker push $(REPOPREFIX)/scarecrow:latest
	docker push $(REPOPREFIX)/webshell-server:latest
	docker push $(REPOPREFIX)/tensorsec-webhook:latest
	docker push $(REPOPREFIX)/tensorsec-cluster-manager:latest
endif

.PHONY: retag
retag:
ifeq ($(USERELEASE),true)
	@echo "tag all images release"
	docker tag $(REPOPREFIX)/tensorsec-console:latest $(REPOPREFIX)/tensorsec-console:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/tensorsec-scanner:latest $(REPOPREFIX)/tensorsec-scanner:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/kube-bench:latest $(REPOPREFIX)/kube-bench:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/docker-bench-security:latest $(REPOPREFIX)/docker-bench-security:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/host-bench:latest $(REPOPREFIX)/host-bench:$(RELEASEVERSION)
	#docker tag $(REPOPREFIX)/tensordig:latest $(REPOPREFIX)/tensordig:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/tensorsec-cleaner:latest $(REPOPREFIX)/tensorsec-cleaner:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/tensorsec-drift-prevention:latest $(REPOPREFIX)/tensorsec-drift-prevention:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/tensorsec-drift-prevention-client:latest $(REPOPREFIX)/tensorsec-drift-prevention-client:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/faulty:latest $(REPOPREFIX)/faulty:$(RELEASEVERSION)
	#docker tag $(REPOPREFIX)/tensorsec-seccomp-generator:latest $(REPOPREFIX)/tensorsec-seccomp-generator:$(RELEASEVERSION)
	#docker tag $(REPOPREFIX)/tensorsec-seccomp-generator-webhook:latest $(REPOPREFIX)/tensorsec-seccomp-generator-webhook:$(RELEASEVERSION)
	# docker tag $(REPOPREFIX)/tensorsec-go-audit:latest $(REPOPREFIX)/tensorsec-go-audit:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/tensorsec-holmes:latest $(REPOPREFIX)/tensorsec-holmes:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/tensorsec-daemon:latest $(REPOPREFIX)/tensorsec-daemon:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/tensorsec-image-validator:latest $(REPOPREFIX)/tensorsec-image-validator:$(RELEASEVERSION)
	#docker tag $(REPOPREFIX)/scarecrow:latest $(REPOPREFIX)/scarecrow:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/webshell-server:latest $(REPOPREFIX)/webshell-server:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/tensorsec-webhook:latest $(REPOPREFIX)/tensorsec-webhook:$(RELEASEVERSION)
	docker tag $(REPOPREFIX)/tensorsec-cluster-manager:latest $(REPOPREFIX)/cluster-manager:$(RELEASEVERSION)
else
	@echo "tag all images latest"
	docker tag $(REPOPREFIXOLD)/tensorsec-console:latest $(REPOPREFIX)/tensorsec-console:latest
	docker tag $(REPOPREFIXOLD)/tensorsec-scanner:latest $(REPOPREFIX)/tensorsec-scanner:latest
	docker tag $(REPOPREFIXOLD)/kube-bench:latest $(REPOPREFIX)/kube-bench:latest
	docker tag $(REPOPREFIXOLD)/docker-bench-security:latest $(REPOPREFIX)/docker-bench-security:latest
	docker tag $(REPOPREFIXOLD)/host-bench:latest $(REPOPREFIX)/host-bench:latest
	#docker tag $(REPOPREFIXOLD)/tensordig:latest $(REPOPREFIX)/tensordig:latest
	docker tag $(REPOPREFIXOLD)/tensorsec-cleaner:latest $(REPOPREFIX)/tensorsec-cleaner:latest
	docker tag $(REPOPREFIXOLD)/tensorsec-drift-prevention:latest $(REPOPREFIX)/tensorsec-drift-prevention:latest
	docker tag $(REPOPREFIXOLD)/tensorsec-drift-prevention-client:latest $(REPOPREFIX)/tensorsec-drift-prevention-client:latest
	docker tag $(REPOPREFIXOLD)/faulty:latest $(REPOPREFIX)/faulty:latest
	#docker tag $(REPOPREFIXOLD)/tensorsec-seccomp-generator:latest $(REPOPREFIX)/tensorsec-seccomp-generator:latest
	#docker tag $(REPOPREFIXOLD)/tensorsec-seccomp-generator-webhook:latest $(REPOPREFIX)/tensorsec-seccomp-generator-webhook:latest
	# docker tag $(REPOPREFIXOLD)/tensorsec-go-audit:latest $(REPOPREFIX)/tensorsec-go-audit:latest
	docker tag $(REPOPREFIXOLD)/tensorsec-holmes:latest $(REPOPREFIX)/tensorsec-holmes:latest
	docker tag $(REPOPREFIXOLD)/tensorsec-daemon:latest $(REPOPREFIX)/tensorsec-daemon:latest
	docker tag $(REPOPREFIXOLD)/tensorsec-image-validator:latest $(REPOPREFIX)/tensorsec-image-validator:latest
	#docker tag $(REPOPREFIXOLD)/scarecrow:latest $(REPOPREFIX)/scarecrow:latest
	docker tag $(REPOPREFIXOLD)/webshell-server:latest $(REPOPREFIX)/webshell-server:latest
	docker tag $(REPOPREFIXOLD)/tensorsec-webhook:latest $(REPOPREFIX)/tensorsec-webhook:latest
	docker tag $(REPOPREFIX)/tensorsec-cluster-manager:latest $(REPOPREFIX)/cluster-manager:latest
endif

.PHONY: redeploy
redeploy:
	# DO NOT USE THIS FOR PRODUCTION ENVIRONMENT
	# It will wipe out customer data.
	@echo "+ $@"
	cd deployments/helm; \
		helm delete --purge tensorsec; \
		rm -rf charts; \
		kubectl -n tensorsec patch pvc elasticsearch-master-elasticsearch-master-0 -p '{"metadata":{"finalizers":null}}'; \
		kubectl -n tensorsec delete pvc elasticsearch-master-elasticsearch-master-0; \
		kubectl -n tensorsec patch pvc tensorsec-elasticsearch-master-tensorsec-elasticsearch-master-0 -p '{"metadata":{"finalizers":null}}'; \
		kubectl -n tensorsec delete pvc tensorsec-elasticsearch-master-tensorsec-elasticsearch-master-0; \
		kubectl -n tensorsec patch pvc datadir-tensorsec-mongodb-primary-0 -p '{"metadata":{"finalizers":null}}'; \
		kubectl -n tensorsec delete pvc datadir-tensorsec-mongodb-primary-0; \
		kubectl -n tensorsec patch pvc datadir-tensorsec-mongodb-secondary-0 -p '{"metadata":{"finalizers":null}}'; \
		kubectl -n tensorsec delete pvc datadir-tensorsec-mongodb-secondary-0; \
		kubectl -n tensorsec patch pvc redis-data-tensorsec-redis-master-0 -p '{"metadata":{"finalizers":null}}'; \
		kubectl -n tensorsec delete pvc redis-data-tensorsec-redis-master-0; \
		kubectl -n tensorsec patch pvc redis-data-tensorsec-redis-slave-0 -p '{"metadata":{"finalizers":null}}'; \
		kubectl -n tensorsec delete pvc redis-data-tensorsec-redis-slave-0; \
		kubectl -n tensorsec patch pvc audit-pvc -p '{"metadata":{"finalizers":null}}'; \
		kubectl -n tensorsec delete pvc audit-pvc; \
		kubectl --namespace tensorsec get job --namespace tensorsec | grep "-bench" | awk '{print $2}' | xargs kubectl --namespace tensorsec delete job; \
		helm dep up; \
		helm install ./ --namespace tensorsec --name tensorsec; \
		cd -

.PHONY: cycleConsole
cycleConsole:			## Use only for development! Deletes and recreates console pod
	kubectl scale --replicas=0 deployment/tensorsec-console
	kubectl scale --replicas=1 deployment/tensorsec-console

.PHONY: forwardConsole
forwardConsole:			## Use only for development! Creates kubernetes port-forward to project APIs
	- ps aux | grep port-forward | head -1 | awk -c '{print $$2}' | xargs kill
	kubectl port-forward service/tensorsec-console --address 0.0.0.0 8889:8889 &
