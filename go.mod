module gitlab.com/piccolo_su/vegeta

go 1.13

require (
	github.com/360EntSecGroup-Skylar/excelize v1.4.1
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/PuerkitoBio/goquery v1.6.0
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/apex/log v1.9.0 // indirect
	github.com/containerd/containerd v1.3.1 // indirect
	github.com/containerd/continuity v0.0.0-20191214063359-1097c8bae83b // indirect
	github.com/coreos/etcd v3.3.17+incompatible // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v0.7.3-0.20190813234819-fade624f1696
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c // indirect
	github.com/elazarl/goproxy v0.0.0-20201021153353-00ad82a08272 // indirect
	github.com/facebookarchive/freeport v0.0.0-20150612182905-d4adf43b75b9
	github.com/gin-gonic/gin v1.4.0
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-chi/jwtauth v4.0.3+incompatible
	github.com/go-openapi/spec v0.19.9 // indirect
	github.com/go-openapi/swag v0.19.9 // indirect
	github.com/go-redis/redis/v8 v8.3.2
	github.com/golang/gddo v0.0.0-20190904175337-72a348e765d2
	github.com/gorilla/securecookie v1.1.1
	github.com/heroku/docker-registry-client v0.0.0-20190909225348-afc9e1acc3d5
	github.com/jinzhu/gorm v1.9.16
	github.com/json-iterator/go v1.1.10
	github.com/lib/pq v1.8.0
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
	github.com/minio/minio v0.0.0-20201122074850-39f3d5493bc9 // indirect
	github.com/morikuni/aec v1.0.0 // indirect; indirectgo
	github.com/mosn/registry v0.0.0-20210108061200-d7b63bc1904b // indirect
	github.com/oceanicdev/chi-param v1.1.0
	github.com/olivere/elastic/v7 v7.0.21
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/robfig/cron/v3 v3.0.1
	github.com/rs/zerolog v1.17.2
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	github.com/swaggo/http-swagger v0.0.0-20190614090009-c2865af9083e
	github.com/swaggo/swag v1.6.7 // indirect
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	gitlab.com/tensorsecurity-rd/gobpf v0.0.0
	go.etcd.io/etcd v3.3.17+incompatible
	go.mongodb.org/mongo-driver v1.4.4
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45 // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.0.0-20190918195907-bd6ac527cfd2
	k8s.io/apimachinery v0.0.0-20191004074956-01f8b7d1121a
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/utils v0.0.0-20191114200735-6ca3b61696b6 // indirect
	sigs.k8s.io/controller-runtime v0.3.0
)

replace gitlab.com/tensorsecurity-rd/gobpf => ./configs/tensordig/gobpf
