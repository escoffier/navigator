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
            git changelog: false, credentialsId: '35006a79-98ed-4b4e-8afa-1bc3e60a621c', poll: false, url: 'http://10.77.107.13/root/tensornavigator.git'
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
                sed -i  's#GO111MODULE=on#GO111MODULE=on GOPROXY=https://goproxy.cn#g' configs/scap/jobs/kube-bench/Dockerfile
                sed -i 's#DOCKER_REGISTRY=$(REPOPREFIX)#DOCKER_REGISTRY=registry.t-appagile.com/tensorsecurity#g' Makefile
                sed -i 's#REPOPREFIX?=localhost:32000#REPOPREFIX?=registry.t-appagile.com/tensorsecurity#g' Makefile
                mkdir ~/.kube/
                cp ~/.docker/config ~/.kube/config
                cp ~/.docker/kubectl /bin/
                chmod +755 /bin/kubectl
                '''
                if("$moduleToDeploy".trim() == "console") {
                sh '''
                export GOPROXY=https://goproxy.cn
                export GO111MODULE=on
                make console
                docker push registry.t-appagile.com/tensorsecurity/tensorsec-console:latest
                kubectl scale --replicas=0 deployment tensorsec-console  -n tensorsec
                kubectl scale --replicas=1 deployment tensorsec-console  -n tensorsec
                '''
                }
                if("$moduleToDeploy".trim() == "redeploy") {
                sh '''
                cp ~/.docker/helm /bin/
                scp -r 172.21.0.5:~/.helm/  /root/
                sed -i 's#ourDockerRepo: 192.168.1.203:5000#ourDockerRepo: registry.t-appagile.com/tensorsecurity#g' deployments/helm/values.yaml
                make redeploy
                '''
                }
                if("$moduleToDeploy".trim() == "all") {
                sh '''
                echo "test"
                export GOPROXY=https://goproxy.cn
                export GO111MODULE=on
                USEMIRROR=true make all
                make pushimages
                kubectl scale --replicas=0 deploy/tensorsec-console deploy/tensorsec-scanner -n tensorsec
                kubectl scale --replicas=1 deploy/tensorsec-console deploy/tensorsec-scanner -n tensorsec
                '''
                }
                if("$moduleToDeploy".trim() == "scap-jobs") {
                sh '''
                export GOPROXY=https://goproxy.cn
                export GO111MODULE=on
                USEMIRROR=true scap-jobs
                docker push registry.t-appagile.com/tensorsecurity/docker-bench-security:latest
                docker push registry.t-appagile.com/tensorsecurity/kube-bench:latest
                docker push registry.t-appagile.com/tensorsecurity/host-bench:latest
                '''
                }
                if("$moduleToDeploy".trim() == "scanner") {
                sh '''
                export GOPROXY=https://goproxy.cn
                export GO111MODULE=on
                make scanner
                docker push registry.t-appagile.com/tensorsecurity/tensorsec-scanner:latest
                kubectl scale --replicas=0 deploy/tensorsec-scanner -n tensorsec
                kubectl scale --replicas=1 deploy/tensorsec-scanner -n tensorsec              
                '''
                }
            }
        }
    }
}