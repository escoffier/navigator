module gitlab.com/piccolo_su/vegeta

go 1.15

require (
	github.com/360EntSecGroup-Skylar/excelize v1.4.1
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/PuerkitoBio/goquery v1.6.0
	github.com/avast/retry-go v3.0.0+incompatible
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
	github.com/globalsign/mgo v0.0.0-20181015135952-eeefdecb41b8
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-chi/jwtauth v4.0.3+incompatible
	github.com/go-openapi/spec v0.19.9 // indirect
	github.com/go-openapi/swag v0.19.9 // indirect
	github.com/go-redis/redis/v8 v8.3.2
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golang/gddo v0.0.0-20190904175337-72a348e765d2
	github.com/golang/protobuf v1.4.2
	github.com/google/uuid v1.1.1 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gorilla/securecookie v1.1.1
	github.com/heroku/docker-registry-client v0.0.0-20190909225348-afc9e1acc3d5
	github.com/jackc/pgproto3/v2 v2.0.7 // indirect
	github.com/jackc/pgx/v4 v4.11.0 // indirect
	github.com/jinzhu/gorm v1.9.16
	github.com/json-iterator/go v1.1.10
	github.com/klauspost/compress v1.10.3 // indirect
	github.com/kr/pretty v0.2.0 // indirect
	github.com/lib/pq v1.8.0
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
	github.com/morikuni/aec v1.0.0 // indirect; indirectgo
	github.com/mozilla/tls-observatory v0.0.0-20180409132520-8791a200eb40
	github.com/oceanicdev/chi-param v1.1.0
	github.com/olivere/elastic/v7 v7.0.21
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/rfyiamcool/go-retry v1.0.1
	github.com/robfig/cron/v3 v3.0.1
	github.com/rs/zerolog v1.21.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	github.com/swaggo/http-swagger v0.0.0-20190614090009-c2865af9083e
	github.com/swaggo/swag v1.6.7 // indirect
	github.com/tealeg/xlsx v1.0.5
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	gitlab.com/tensorsecurity-rd/gobpf v0.0.0
	go.etcd.io/bbolt v1.3.5 // indirect
	go.etcd.io/etcd v3.3.17+incompatible
	go.mongodb.org/mongo-driver v1.5.1
	go.uber.org/atomic v1.6.0
	go.uber.org/zap v1.14.1 // indirect
	golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9
	google.golang.org/genproto v0.0.0-20191108220845-16a3f7862a1a
	google.golang.org/grpc v1.29.1
	google.golang.org/protobuf v1.23.0
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/yaml.v2 v2.3.0
	gopkg.in/yaml.v3 v3.0.0-20200605160147-a5ece683394c // indirect
	gorm.io/driver/postgres v1.0.8
	gorm.io/gorm v1.21.8
	k8s.io/api v0.0.0-20190918195907-bd6ac527cfd2
	k8s.io/apimachinery v0.0.0-20191004074956-01f8b7d1121a
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/utils v0.0.0-20191114200735-6ca3b61696b6 // indirect
	sigs.k8s.io/controller-runtime v0.3.0
)

replace gitlab.com/tensorsecurity-rd/gobpf => ./configs/tensordig/gobpf
