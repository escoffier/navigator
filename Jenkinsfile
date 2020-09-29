def label = "jenkins-slave-golang"
def moduleToDeploy = "${env.MODULE}"

podTemplate(label: "jenkins-slave-golang",cloud: "kubernetes" ){
    node (label) {
        wrap([$class: 'BuildUser']) {
        script {
            BUILD_USER_ID = "${env.BUILD_USER_ID}"
            BUILD_USER = "${env.BUILD_USER}"
            BUILD_USER_EMAIL = "${env.BUILD_USER_EMAIL}"
            }
		}
        addShortText(
        text: "$moduleToDeploy",
        color: "red"
        )
        addShortText(
        text: "$BUILD_USER_ID",
        color: "green"
        )
        stage('git clone'){
            container('golang') {
            git credentialsId: 'ab33d484-a7a7-4ba8-acfe-5c3d5e695f64', url: 'https://gitlab.com/tensorsecurity-rd/tensornavigator.git'
        }
        }
        stage('build all'){
            container('golang') {
                sh '''
                export GOPROXY=https://goproxy.cn
                export GO111MODULE=on
                git submodule init
                git submodule update
                go get -u github.com/swaggo/swag/cmd/swag
                go get -u golang.org/x/lint/golint
                npm conf set registry https://registry.npm.taobao.org
                npm config set loglevel info
                sed -i  's#GO111MODULE=on#GO111MODULE=on GOPROXY=https://goproxy.cn#g' configs/scap/jobs/kube-bench/Dockerfile
                sed -i 's#alpine.global.ssl.fastly.net#mirrors.aliyun.com#g' configs/scap/jobs/docker-bench-security/Dockerfile
                sed -i 's#DOCKER_REGISTRY=$(REPOPREFIX)#DOCKER_REGISTRY=registry.t-appagile.com/tensorsecurity#g' Makefile
                sed -i 's#REPOPREFIX?=localhost:32000#REPOPREFIX?=registry.t-appagile.com/tensorsecurity#g' Makefile
                mkdir ~/.kube/
                cp ~/.docker/config ~/.kube/config
                cp ~/.docker/kubectl /bin/
                chmod +755 /bin/kubectl
                npm conf set registry https://registry.npm.taobao.org
                npm config set loglevel info
                '''
                if("$moduleToDeploy".trim() == "console") {
                sh '''
                cd cmd/console/frontend/ && npm install && cd -
                export GOPROXY=https://goproxy.cn
                export GO111MODULE=on
                make frontend
                make console
                docker push registry.t-appagile.com/tensorsecurity/vegeta-console:latest
                kubectl scale --replicas=0 deployment  console  -n vegeta
                kubectl scale --replicas=1 deployment  console  -n vegeta
                '''
                }
                if("$moduleToDeploy".trim() == "all") {
                sh '''
                make all
                make pushimages
                kubectl scale --replicas=0 deploy/console deploy/scanner deploy/alerter -n vegeta
                '''
                }
                if("$moduleToDeploy".trim() == "scap-jobs") {
                sh '''
                export GOPROXY=https://goproxy.cn
                export GO111MODULE=on
                make scap-jobs
                docker push registry.t-appagile.com/tensorsecurity/docker-bench-security:latest
                docker push registry.t-appagile.com/tensorsecurity/kube-bench:latest
                docker push registry.t-appagile.com/tensorsecurity/host-bench:latest
                '''
                }
                if("$moduleToDeploy".trim() == "alerter") {
                sh '''
                export GOPROXY=https://goproxy.cn
                export GO111MODULE=on
                make alerter
                docker push registry.t-appagile.com/tensorsecurity/vegeta-alerter:latest
                kubectl scale --replicas=0 deploy/vegeta-alerter -n vegeta
                kubectl scale --replicas=1 deploy/vegeta-alerter -n vegeta
                '''
                }
                if("$moduleToDeploy".trim() == "daemon") {
                sh '''
                export GOPROXY=https://goproxy.cn
                export GO111MODULE=on
                make daemon
                docker push registry.t-appagile.com/tensorsecurity/vegeta-daemon:latest
                '''
                }
                if("$moduleToDeploy".trim() == "scanner") {
                sh '''
                export GOPROXY=https://goproxy.cn
                export GO111MODULE=on
                make scanner
                docker push registry.t-appagile.com/tensorsecurity/vegeta-scanner:latest
                kubectl scale --replicas=0 deploy/scanner -n vegeta
                kubectl scale --replicas=1 deploy/scanner -n vegeta                
                '''
                }
            }
        }
    }
}
