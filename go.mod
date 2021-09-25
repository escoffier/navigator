module gitlab.com/piccolo_su/vegeta

go 1.16

require (
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/PuerkitoBio/goquery v1.6.0
	github.com/ReneKroon/ttlcache/v2 v2.8.1
	github.com/agnivade/levenshtein v1.1.1
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/armon/go-metrics v0.3.9 // indirect
	github.com/avast/retry-go v3.0.0+incompatible
	github.com/badoux/checkmail v1.2.1
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/containerd/continuity v0.0.0-20191214063359-1097c8bae83b // indirect
	github.com/dchest/captcha v0.0.0-20200903113550-03f5f0333e1f
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v17.12.0-ce-rc1.0.20210128214336-420b1d36250f+incompatible
	github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c // indirect
	github.com/elastic/go-libaudit/v2 v2.2.0
	github.com/elazarl/goproxy v0.0.0-20201021153353-00ad82a08272 // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible
	github.com/facebookarchive/freeport v0.0.0-20150612182905-d4adf43b75b9
	github.com/falcosecurity/client-go v0.3.0
	github.com/fatih/color v1.12.0 // indirect
	github.com/florianl/go-conntrack v0.2.0 //conntrack
	github.com/gin-gonic/gin v1.7.4
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/jwtauth v4.0.4+incompatible
	github.com/go-openapi/spec v0.19.9 // indirect
	github.com/go-openapi/swag v0.19.9 // indirect
	github.com/go-playground/validator/v10 v10.9.0 // indirect
	github.com/go-redis/redis/v8 v8.11.3
	github.com/gofrs/uuid v4.0.0+incompatible
	github.com/golang-migrate/migrate/v4 v4.14.1
	github.com/golang/gddo v0.0.0-20190904175337-72a348e765d2
	github.com/golang/protobuf v1.5.2
	github.com/google/go-containerregistry v0.1.2 //ct
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gorilla/securecookie v1.1.1
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/heroku/docker-registry-client v0.0.0-20190909225348-afc9e1acc3d5
	github.com/huaweicloud/huaweicloud-sdk-go-v3 v0.0.59
	github.com/json-iterator/go v1.1.12
	github.com/klauspost/compress v1.13.5 // indirect
	github.com/lib/pq v1.10.3
	github.com/mattn/go-colorable v0.1.8
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
	github.com/minio/highwayhash v1.0.2 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mozilla/tls-observatory v0.0.0-20200317151703-4fa42e1c2dee
	github.com/nats-io/nats-server/v2 v2.4.0 // indirect
	github.com/nats-io/nats-streaming-server v0.22.1 // indirect
	github.com/nats-io/nats.go v1.12.1
	github.com/nats-io/stan.go v0.10.0
	github.com/novln/docker-parser v1.0.0
	github.com/oceanicdev/chi-param v1.1.0
	github.com/olekukonko/tablewriter v0.0.5 //ct
	github.com/olivere/elastic/v7 v7.0.29
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/robfig/cron/v3 v3.0.1
	github.com/rs/zerolog v1.25.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/smartystreets/goconvey v1.6.4
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.7.0
	github.com/swaggo/files v0.0.0-20190704085106-630677cd5c14
	github.com/swaggo/gin-swagger v1.2.0
	github.com/swaggo/http-swagger v0.0.0-20190614090009-c2865af9083e
	github.com/swaggo/swag v1.6.7
	github.com/tealeg/xlsx v1.0.5
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	github.com/tomogoma/generator v0.0.0-20171014125632-4398aab4dd41 // indirect
	github.com/tomogoma/go-api-guard v0.0.0-20180312041446-a2bad766ec64
	github.com/tomogoma/go-typed-errors v0.0.0-20181222204503-0532faf740be
	github.com/ugorji/go v1.2.6 // indirect
	github.com/urfave/cli/v2 v2.1.1
	github.com/vishvananda/netlink v0.0.0 //netlink
	gitlab.com/tensorsecurity-rd/gobpf v0.0.0
	go.mongodb.org/mongo-driver v1.7.2
	go.uber.org/atomic v1.9.0
	go.uber.org/automaxprocs v1.4.0
	go.uber.org/zap v1.13.0
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.0.0-20210907225631-ff17edfbf26d // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210925032602-92d5a993a665
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac // indirect
	google.golang.org/genproto v0.0.0-20210903162649-d08c68adba83
	google.golang.org/grpc v1.40.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/datatypes v1.0.1
	gorm.io/driver/postgres v1.1.1
	gorm.io/gorm v1.21.15
	k8s.io/api v0.19.12
	k8s.io/apimachinery v0.19.12
	k8s.io/apiserver v0.19.12
	k8s.io/client-go v0.19.12
	scm.tensorsecurity.cn/tensorsecurity-rd/cloudwalker v0.0.4
)

replace (
	github.com/vishvananda/netlink => ./configs/daemon/netlink
	gitlab.com/tensorsecurity-rd/go-pkg => ./tensorpkg
	gitlab.com/tensorsecurity-rd/gobpf => ./configs/tensordig/gobpf
)
