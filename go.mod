module gitlab.com/piccolo_su/vegeta

go 1.13

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/PuerkitoBio/goquery v1.6.0
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/apex/log v1.9.0 // indirect
	github.com/containerd/containerd v1.3.1 // indirect
	github.com/containerd/continuity v0.0.0-20191214063359-1097c8bae83b // indirect
	github.com/coreos/etcd v3.3.17+incompatible // indirect
	github.com/dgraph-io/dgo/v200 v200.0.0-20200916081436-9ff368ad829a // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v0.7.3-0.20190813234819-fade624f1696
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c // indirect
	github.com/elastic/go-elasticsearch v0.0.0 // indirect
	github.com/elastic/go-elasticsearch/v8 v8.0.0-20201022194115-1af099fb3eca // indirect
	github.com/elazarl/goproxy v0.0.0-20201021153353-00ad82a08272 // indirect
	github.com/facebookarchive/freeport v0.0.0-20150612182905-d4adf43b75b9
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-chi/jwtauth v4.0.3+incompatible
	github.com/go-openapi/spec v0.19.9 // indirect
	github.com/go-openapi/swag v0.19.9 // indirect
	github.com/go-redis/redis v6.15.9+incompatible // indirect
	github.com/go-redis/redis/v8 v8.3.2
	github.com/golang/gddo v0.0.0-20190904175337-72a348e765d2
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/golang/snappy v0.0.1 // indirect
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/google/uuid v1.1.1 // indirect
	github.com/googleapis/gnostic v0.3.0 // indirect
	github.com/gorilla/securecookie v1.1.1
	github.com/heroku/docker-registry-client v0.0.0-20190909225348-afc9e1acc3d5
	github.com/imdario/mergo v0.3.5 // indirect
	github.com/lib/pq v1.8.0
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
	github.com/minio/minio v0.0.0-20201122074850-39f3d5493bc9 // indirect
	github.com/mitchellh/go-ps v0.0.0-20170309133038-4fdf99ab2936 // indirect
	github.com/morikuni/aec v1.0.0 // indirect; indirectgo
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
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.5.0
	github.com/stretchr/testify v1.6.1
	github.com/swaggo/http-swagger v0.0.0-20190614090009-c2865af9083e
	github.com/swaggo/swag v1.6.7 // indirect
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	github.com/tidwall/pretty v1.0.0 // indirect
	github.com/xdg/scram v0.0.0-20180814205039-7eeb5667e42c // indirect
	github.com/xdg/stringprep v1.0.0 // indirect
	gitlab.com/tensorsecurity-rd/gobpf v0.0.0
	go.etcd.io/etcd v3.3.17+incompatible
	go.mongodb.org/mongo-driver v1.4.4
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45 // indirect
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208 // indirect
	google.golang.org/appengine v1.5.0 // indirect
	google.golang.org/grpc v1.26.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.0.0-20190409021203-6e4e0e4f393b
	k8s.io/apimachinery v0.0.0-20191004074956-01f8b7d1121a
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog v0.3.3 // indirect
	k8s.io/utils v0.0.0-20191114200735-6ca3b61696b6 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)

replace gitlab.com/tensorsecurity-rd/gobpf => ./configs/tensordig/gobpf
