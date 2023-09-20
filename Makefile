VERSION = 0.1.0

## 判断操作系统及内核架构
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

#ifeq ($(UNAME_S),Linux)
#	LDFLAGS = -extldflags "-static"
#endif

## 指定镜像仓库地址: "地址:端口/项目"
REPOPREFIX?=localhost:32000

## 指定镜像tag
IMAGE_TAG?=v0.0.1

## 指定国内源
MIRROR_SOURCE?=mirrors.aliyun.com

## holmes-packages的镜像tag
FETCHTAG?=latest

## base image的tag
BASE_IMAGE_TAG?=latest

## license版本: "sit"/"release"
LICENSE_SECRET?=sit

## 指定bin目录
BIN_DIR = $(shell pwd)/bin/

.PHONY: help
help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'


.PHONY: apiscan-job
apiscan-job:
	@echo "build apiscan-job"
	go build -v \
		-o dist/apiscan gitlab.com/piccolo_su/vegeta/cmd/apiscan-job
	#upx --lzma --best dist/apiscan
	docker build -t $(REPOPREFIX)/apiscan-job:$(IMAGE_TAG) -f ./build/apiscan-job/Dockerfile .


.PHONY: cluster-manager
cluster-manager:
	@echo "build cluster-manager"
	go build -v \
		-tags=jsoniter -o dist/cluster-manager gitlab.com/piccolo_su/vegeta/cmd/clustermanager
	#upx --lzma --best dist/cluster-manager
	docker build -t $(REPOPREFIX)/cluster-manager:$(IMAGE_TAG) -f ./build/cluster-manager/Dockerfile .


.PHONY: cluster-proxy
cluster-proxy:
	@echo "build cluster proxy"
	cp ./build/cluster-proxy/bootstrap.yaml ./bootstrap.yaml
	docker build -t $(REPOPREFIX)/cluster-proxy:$(IMAGE_TAG) -f ./build/cluster-proxy/Dockerfile \
		--build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) .


.PHONY: console
console: 		## Build console binary
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/console/cmd.Version=$(VERSION)" \
		-tags="$(LICENSE_SECRET) jsoniter" -o dist/console gitlab.com/piccolo_su/vegeta/cmd/console
	#upx --lzma --best dist/console

	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/holmes/encodefile/cmd.Version=$(VERSION)" \
		-o dist/holmes-rules-pack gitlab.com/piccolo_su/vegeta/cmd/holmes/encodefile
	#upx --lzma --best dist/holmes-rules-pack
	# generate the holmes rules thr file with version
	./build_holmes_rules_thr.sh

	docker build -t $(REPOPREFIX)/console:$(IMAGE_TAG) -f ./build/console/Dockerfile \
		--build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) .


.PHONY: daemon
daemon: drift-prevention-client ## Build daemon binary
	@echo "+ $@"
	@echo "daemon will use mirror"
	CGO_ENABLED=1 go build -v -o bin/daemon  cmd/daemon/main.go
	gcc -o bin/ns-mnt  cmd/daemon/setns/cjson.c cmd/daemon/setns/setmnt.c cmd/daemon/setns/net_info.c cmd/daemon/setns/netebpf_user.c cmd/daemon/setns/bpf.c cmd/daemon/setns/bpf_load.c -lelf -lpthread
	make -C cmd/daemon/net-policy BIN_DIR=$(BIN_DIR)
	#upx --lzma --best bin/daemon
	docker build -f build/daemon/Dockerfile -t $(REPOPREFIX)/daemon:$(IMAGE_TAG) \
        --build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) .


.PHONY: data
data:  		## Build cleaner binary
	@echo "+ $@"
	CGO_ENABLED=0 go build -v \
		-o dist/cleaner gitlab.com/piccolo_su/vegeta/cmd/data/tool/main
	#upx --lzma --best dist/cleaner
	docker build -t $(REPOPREFIX)/cleaner:$(IMAGE_TAG) -f ./build/data/Dockerfile \
		--build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) .


.PHONY: drift-prevention-client
drift-prevention-client:	## Build drift prevention client binary
	@echo "+ $@"
	cd configs/drift-prevention && ./run.sh mirrors.aliyun.com


.PHONY: faulty
faulty:
	@echo "+ $@"
	@echo "faulty will use mirror"
	docker build -t $(REPOPREFIX)/faulty:$(IMAGE_TAG) -f ./build/faulty/Dockerfile \
		--build-arg REPO=$(REPOPREFIX) --build-arg TAG=$(BASE_IMAGE_TAG) .


.PHONY: faulty-base
faulty-base: ## Build faulty base image
	@echo "+ $@"
ifeq ($(UNAME_M),x86_64)
	docker build -t $(REPOPREFIX)/baseimage-faulty:$(IMAGE_TAG) \
	-f ./build/faulty/baseimage-dockerfile \
	--build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) \
	--build-arg TARGETARCH=amd64 .
else
	docker build -t $(REPOPREFIX)/baseimage-faulty:$(IMAGE_TAG) \
	-f ./build/faulty/baseimage-dockerfile \
	--build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) \
	--build-arg TARGETARCH=arm64 .
endif


.PHONY: holmes
holmes:     ## Build holmes docker
	@echo "+ $@"
	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/holmes/starter/cmd.Version=$(VERSION)" \
		-o dist/holmes-starter gitlab.com/piccolo_su/vegeta/cmd/holmes/starter
ifeq ($(UNAME_M),x86_64)
	docker build -t $(REPOPREFIX)/holmes:$(IMAGE_TAG) -f ./build/holmes/Dockerfile \
		--build-arg REPO=$(REPOPREFIX) --build-arg TAG=$(FETCHTAG) \
		--build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) --build-arg TARGETARCH=amd64 .
else
	docker build -t $(REPOPREFIX)/holmes:$(IMAGE_TAG) -f ./build/holmes/Dockerfile \
		--build-arg REPO=$(REPOPREFIX) --build-arg TAG=$(FETCHTAG) \
		--build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) --build-arg TARGETARCH=arm64 .
endif


.PHONY: kafka-proxy
kafka-proxy:
	@echo "build kafka-proxy"
	go build -v \
		-o dist/kafka-proxy gitlab.com/piccolo_su/vegeta/cmd/kafkaproxy
	#upx --lzma --best dist/kafka-proxy
	docker build -t $(REPOPREFIX)/kafka-proxy:$(IMAGE_TAG) -f ./build/kafka-proxy/Dockerfile .


.PHONY: kube-scanner-report
kube-scanner-report: 
	@echo "+ $@"
	CGO_ENABLED=0 go build -v \
    		-o dist/kube-scanner-report gitlab.com/piccolo_su/vegeta/cmd/kube-scanner-report
	#upx --lzma --best dist/kube-scanner-report
	docker build -t $(REPOPREFIX)/kube-scanner-report:$(IMAGE_TAG) -f ./build/kube-scanner-report/Dockerfile .


.PHONY: node-image 
node-image:  ## Build node-image binary
	@echo "+ $@"
	@echo "node-image will use mirror"
	CGO_ENABLED=1 go build -v -o dist/node-image cmd/node-image/main.go
	#upx --lzma --best dist/node-image
	docker build -f build/node-image/Dockerfile -t $(REPOPREFIX)/node-image:$(IMAGE_TAG) \
		--build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) .


.PHONY: platform-report
platform-report: 
	@echo "+ $@"
	CGO_ENABLED=0 go build -v \
    		-o dist/platform-report gitlab.com/piccolo_su/vegeta/cmd/platform-report
	#upx --lzma --best dist/platform-report
	docker build -t $(REPOPREFIX)/platform-report:$(IMAGE_TAG) -f ./build/platform-report/Dockerfile .


.PHONY: scan_report
scan_report: 		## Build cleaner binary
	@echo "+ $@"
	CGO_ENABLED=1 go build -trimpath -v \
		-o dist/scan_report cmd/scanner/bin/scan-report/main.go
	#upx --lzma --best dist/scan_report
	docker build -t $(REPOPREFIX)/scan-report:$(IMAGE_TAG) -f ./build/scan_report/Dockerfile \
		--build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) .


.PHONY: scanner
scanner:		## Build scanner binary
	@echo "+ $@"
	CGO_ENABLED=1	go build -v \
		--ldflags "$(LDFLAGS) -X gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd.Version=$(VERSION)" \
		-tags=jsoniter -o dist/scanner gitlab.com/piccolo_su/vegeta/cmd/scanner
	#upx --lzma --best dist/scanner
	docker build -t $(REPOPREFIX)/scanner:$(IMAGE_TAG) -f ./build/scanner/Dockerfile \
		--build-arg MIRROR_SOURCE=$(MIRROR_SOURCE) .


.PHONY: scarecrow
scarecrow:   ## Build scarecrow docker to test CVEs
	@echo "+ $@"
	@echo "scarecrow will use mirror"
	docker build -t $(REPOPREFIX)/waston-redis:$(IMAGE_TAG) -f ./build/scarecrow/Dockerfile \
		--build-arg REPO=$(REPOPREFIX) .


.PHONY: webhook
webhook:
	@echo "build webhook"
	go build -v \
		-tags=jsoniter -o dist/webhook gitlab.com/piccolo_su/vegeta/cmd/webhook
	#upx --lzma --best dist/webhook
	docker build -t $(REPOPREFIX)/webhook:$(IMAGE_TAG) -f ./build/webhook/Dockerfile .


## Build all images
.PHONY: all
all: drift-prevention-client faulty scanner scarecrow console data holmes daemon  \
webhook cluster-manager kafka-proxy kube-scanner-report platform-report \
scan_report apiscan-job cluster-proxy node-image


.PHONY: pushimages
pushimages:
	@echo "push all images release"
	docker push $(REPOPREFIX)/console:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/scanner:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/cleaner:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/faulty:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/holmes:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/daemon:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/waston-redis:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/webhook:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/cluster-manager:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/kafka-proxy:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/kube-scanner-report:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/platform-report:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/scan-report:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/apiscan-job:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/cluster-proxy:$(IMAGE_TAG)
	docker push $(REPOPREFIX)/node-image:$(IMAGE_TAG)

.PHONY: rm-local-images
rm-local-images:
	@echo "rm all local images $(IMAGE_TAG)"
	docker rmi $(REPOPREFIX)/console:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/scanner:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/cleaner:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/faulty:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/holmes:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/daemon:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/waston-redis:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/webhook:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/cluster-manager:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/kafka-proxy:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/kube-scanner-report:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/scan-report:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/apiscan-job:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/platform-report:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/cluster-proxy:$(IMAGE_TAG)
	docker rmi $(REPOPREFIX)/node-image:$(IMAGE_TAG)
