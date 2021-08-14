module gitlab.com/piccolo_su/vegeta

go 1.15

require (
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/PuerkitoBio/goquery v1.6.0
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/avast/retry-go v3.0.0+incompatible
	github.com/badoux/checkmail v1.2.1
	github.com/containerd/continuity v0.0.0-20191214063359-1097c8bae83b // indirect
	github.com/dchest/captcha v0.0.0-20200903113550-03f5f0333e1f
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v17.12.0-ce-rc1.0.20200618181300-9dc6525e6118+incompatible
	github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c // indirect
	github.com/elazarl/goproxy v0.0.0-20201021153353-00ad82a08272 // indirect
	github.com/facebookarchive/freeport v0.0.0-20150612182905-d4adf43b75b9
	github.com/florianl/go-conntrack v0.2.0 //conntrack
	github.com/gin-gonic/gin v1.7.2
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/jwtauth v4.0.4+incompatible
	github.com/go-openapi/spec v0.19.9 // indirect
	github.com/go-openapi/swag v0.19.9 // indirect
	github.com/go-playground/validator/v10 v10.8.0 // indirect
	github.com/go-redis/redis/v8 v8.11.0
	github.com/gofrs/uuid v4.0.0+incompatible
	github.com/golang-migrate/migrate/v4 v4.14.1
	github.com/golang/gddo v0.0.0-20190904175337-72a348e765d2
	github.com/golang/protobuf v1.5.2
	github.com/google/go-containerregistry v0.1.2 //ct
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/googleapis/gnostic v0.4.0 //indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gorilla/securecookie v1.1.1
	github.com/heroku/docker-registry-client v0.0.0-20190909225348-afc9e1acc3d5
	github.com/jackc/pgx/v4 v4.13.0 // indirect
	github.com/json-iterator/go v1.1.11
	github.com/klauspost/compress v1.10.3 // indirect
	github.com/lib/pq v1.10.2
	github.com/mattn/go-colorable v0.1.6
	github.com/mattn/go-isatty v0.0.13 // indirect
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mozilla/tls-observatory v0.0.0-20200317151703-4fa42e1c2dee
	github.com/oceanicdev/chi-param v1.1.0
	github.com/olekukonko/tablewriter v0.0.5 //ct
	github.com/olivere/elastic/v7 v7.0.26
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/robfig/cron/v3 v3.0.1
	github.com/rs/zerolog v1.23.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
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
	go.mongodb.org/mongo-driver v1.7.0
	go.uber.org/atomic v1.9.0
	go.uber.org/multierr v1.7.0 // indirect
	go.uber.org/zap v1.18.1
	golang.org/x/net v0.0.0-20210716203947-853a461950ff // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c
	google.golang.org/genproto v0.0.0-20210629200056-84d6f6074151
	google.golang.org/grpc v1.39.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/datatypes v1.0.1
	gorm.io/driver/postgres v1.1.0
	gorm.io/gorm v1.21.12
	k8s.io/api v0.17.17
	k8s.io/apimachinery v0.17.18-rc.0
	k8s.io/client-go v0.17.17
	k8s.io/utils v0.0.0-20191114200735-6ca3b61696b6 // indirect
	sigs.k8s.io/controller-runtime v0.3.0
	sigs.k8s.io/yaml v1.2.0 // indirect
)

replace (
	github.com/vishvananda/netlink => ./configs/daemon/netlink
	gitlab.com/tensorsecurity-rd/gobpf => ./configs/tensordig/gobpf
)
