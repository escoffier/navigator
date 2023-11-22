module gitlab.com/piccolo_su/vegeta

go 1.21

require (
	github.com/PuerkitoBio/goquery v1.8.0
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/avast/retry-go v3.0.0+incompatible
	github.com/badoux/checkmail v1.2.1
	github.com/boltdb/bolt v1.3.1
	github.com/dchest/captcha v1.0.0
	github.com/docker/distribution v2.8.2+incompatible
	github.com/docker/docker v23.0.0-rc.1+incompatible
	github.com/elazarl/goproxy v0.0.0-20220901064549-fbd10ff4f5a1 // indirect
	github.com/emicklei/go-restful v2.16.0+incompatible
	github.com/falcosecurity/client-go v0.5.1
	github.com/fatih/color v1.13.0
	github.com/florianl/go-conntrack v0.4.0 //conntrack
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gin-gonic/gin v1.9.1
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-openapi/spec v0.19.9 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/go-playground/validator/v10 v10.14.1 // indirect
	github.com/go-redis/redis/v8 v8.11.5
	github.com/gofrs/uuid v4.4.0+incompatible // indirect
	github.com/golang-migrate/migrate/v4 v4.14.1
	github.com/golang/gddo v0.0.0-20210115222349-20d68f94ee1f
	github.com/google/go-containerregistry v0.13.0 //ct
	github.com/heroku/docker-registry-client v0.0.0-20211012143308-9463674c8930
	github.com/huaweicloud/huaweicloud-sdk-go-v3 v0.0.59
	github.com/json-iterator/go v1.1.12
	github.com/lib/pq v1.10.9 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mozilla/tls-observatory v0.0.0-20210609171429-7bc42856d2e5
	github.com/nats-io/nats.go v1.15.0
	github.com/nats-io/stan.go v0.10.2
	github.com/novln/docker-parser v1.0.0
	github.com/oceanicdev/chi-param v1.1.0
	github.com/olekukonko/tablewriter v0.0.5 // indirect; ct
	github.com/olivere/elastic/v7 v7.0.32
	github.com/opencontainers/go-digest v1.0.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/quay/clair/v2 v2.1.7
	github.com/robfig/cron/v3 v3.0.1
	github.com/rs/zerolog v1.29.1
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.11.0
	github.com/stretchr/testify v1.8.4
	github.com/swaggo/swag v1.6.7
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	github.com/tomogoma/generator v0.0.0-20171014125632-4398aab4dd41 // indirect
	github.com/tomogoma/go-api-guard v0.0.0-20180312041446-a2bad766ec64
	github.com/tomogoma/go-typed-errors v0.0.0-20181222204503-0532faf740be
	github.com/urfave/cli/v2 v2.3.0
	github.com/yeka/zip v0.0.0-20180914125537-d046722c6feb
	go.mongodb.org/mongo-driver v1.8.2
	go.uber.org/automaxprocs v1.5.2
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/net v0.11.0
	golang.org/x/sync v0.2.0
	golang.org/x/sys v0.9.0
	golang.org/x/time v0.3.0
	google.golang.org/grpc v1.56.1
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/datatypes v1.0.3
	gorm.io/driver/postgres v1.4.6
	gorm.io/gorm v1.25.1
	k8s.io/api v0.27.2
	k8s.io/apimachinery v0.27.2
	k8s.io/apiserver v0.27.2
	k8s.io/client-go v0.27.2
	scm.tensorsecurity.cn/tensorsecurity-rd/cloudwalker v0.0.5
	scm.tensorsecurity.cn/tensorsecurity-rd/falcosider v0.2.62
	scm.tensorsecurity.cn/tensorsecurity-rd/trivy v1.0.5
)

require github.com/go-ldap/ldap/v3 v3.4.1

require (
	github.com/March-deng/godisearch v0.0.0-20230510033050-3ae5e895e766
	github.com/afex/hystrix-go v0.0.0-20180502004556-fa1af6a1f4f5
	github.com/agnivade/levenshtein v1.1.1
	github.com/ahmetb/go-linq/v3 v3.2.0
	github.com/apache/pulsar-client-go v0.11.0
	github.com/containernetworking/plugins v1.2.0
	github.com/dlclark/regexp2 v1.8.1
	github.com/elastic/go-libaudit/v2 v2.2.0
	github.com/facebookarchive/freeport v0.0.0-20150612182905-d4adf43b75b9
	github.com/ghodss/yaml v1.0.0
	github.com/gin-contrib/pprof v1.4.0
	github.com/go-redis/redismock/v8 v8.11.5
	github.com/go-redsync/redsync/v4 v4.7.1
	github.com/go-sql-driver/mysql v1.7.1
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572
	github.com/gobwas/glob v0.2.3
	github.com/goccy/go-json v0.10.2
	github.com/golang-jwt/jwt/v5 v5.0.0
	github.com/golang/protobuf v1.5.3
	github.com/google/cadvisor v0.44.1
	github.com/gorilla/handlers v1.5.1
	github.com/imroc/req/v3 v3.35.1
	github.com/jarcoal/httpmock v1.2.0
	github.com/jellydator/ttlcache/v3 v3.0.0
	github.com/jinzhu/copier v0.3.2
	github.com/panjf2000/ants/v2 v2.7.4
	github.com/pquerna/otp v1.4.0
	github.com/rookie-ninja/rk-entry v1.0.11
	github.com/rookie-ninja/rk-gin v1.2.22
	github.com/segmentio/kafka-go v0.4.40
	github.com/shirou/gopsutil/v3 v3.22.12
	github.com/shopspring/decimal v1.3.1
	github.com/sony/gobreaker v0.5.0
	github.com/tealeg/xlsx/v3 v3.3.0
	github.com/xuri/excelize/v2 v2.6.0
	gitlab.com/security-rd/go-pkg v0.2.77
	go.uber.org/atomic v1.11.0
	golang.org/x/exp v0.0.0-20230522175609-2e198f4a06a1
	gomodules.xyz/jsonpatch/v3 v3.0.1
	google.golang.org/protobuf v1.30.0
	gorm.io/driver/sqlite v1.4.3
	k8s.io/cri-api v0.26.2
	k8s.io/klog/v2 v2.90.1
	k8s.io/kubernetes v1.24.0
	layeh.com/radius v0.0.0-20210819152912-ad72663a72ab
	moul.io/http2curl v1.0.0
	scm.tensorsecurity.cn/tensorsecurity-rd/api v0.2.4-0.20230809062140-8296db0e9feb
	scm.tensorsecurity.cn/tensorsecurity-rd/trivy-db v0.0.5
)

require (
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20230106234847-43070de90fa1 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20221215162035-5330a85ea652 // indirect
	github.com/containerd/typeurl/v2 v2.1.0 // indirect
	github.com/moby/sys/signal v0.7.0 // indirect
)

require (
	cloud.google.com/go/compute v1.19.1 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v0.13.0 // indirect
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/99designs/keyring v1.2.1 // indirect
	github.com/AthenZ/athenz v1.10.39 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/CyrusF/go-bayesian v0.0.0-20180928040635-c6aa877814bd // indirect
	github.com/CyrusF/libsvm-go v0.0.0-20180928035651-2210b124fd3d // indirect
	github.com/DataDog/zstd v1.5.0 // indirect
	github.com/MakeNowJust/heredoc v1.0.0 // indirect
	github.com/Masterminds/semver/v3 v3.2.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.3 // indirect
	github.com/Masterminds/squirrel v1.5.4 // indirect
	github.com/Shopify/sarama v1.38.1 // indirect
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d // indirect
	github.com/alecthomas/chroma v0.10.0 // indirect
	github.com/andres-erbsen/clock v0.0.0-20160526145045-9e14626cd129 // indirect
	github.com/ardielle/ardielle-go v1.5.2 // indirect
	github.com/armon/go-metrics v0.3.11 // indirect
	github.com/asaskevich/govalidator v0.0.0-20200428143746-21a406dcc535 // indirect
	github.com/aws/aws-sdk-go-v2 v1.18.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.18.27 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.26 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.35 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.19.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.16.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/athena v1.30.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.26.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.27.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.26.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.22.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.20.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/docdb v1.21.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.20.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.103.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecr v1.18.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecs v1.28.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/efs v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/eks v1.27.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.27.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.19.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticsearchservice v1.19.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/emr v1.27.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/iam v1.21.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.7.28 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.28 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.14.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/kafka v1.20.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.17.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.23.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/lambda v1.37.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/mq v1.15.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/neptune v1.20.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/rds v1.46.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/redshift v1.28.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.36.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.19.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/sns v1.20.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sqs v1.23.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.19.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/workspaces v1.28.15 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.4.0 // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/bytedance/sonic v1.9.1 // indirect
	github.com/chai2010/gettext-go v1.0.2 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
	github.com/chzyer/readline v1.5.1 // indirect
	github.com/cloudflare/circl v1.1.0 // indirect
	github.com/containerd/continuity v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/ttrpc v1.2.1 // indirect
	github.com/containernetworking/cni v1.1.2 // indirect
	github.com/containers/buildah v1.23.1 // indirect
	github.com/containers/common v0.44.5 // indirect
	github.com/containers/image/v5 v5.17.0 // indirect
	github.com/containers/libtrust v0.0.0-20190913040956-14b96171aa3b // indirect
	github.com/containers/ocicrypt v1.1.6 // indirect
	github.com/containers/psgo v1.7.1 // indirect
	github.com/containers/storage v1.37.1 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cri-o/ocicni v0.2.1-0.20210621164014-d0acc7862283 // indirect
	github.com/cyphar/filepath-securejoin v0.2.3 // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/disiqueira/gotree/v3 v3.0.2 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/dvsekhvalnov/jose2go v1.5.0 // indirect
	github.com/eapache/go-resiliency v1.3.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20230111030713-bf00bc1b83b6 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/emicklei/go-restful/v3 v3.10.1 // indirect
	github.com/evanphx/json-patch v5.6.0+incompatible // indirect
	github.com/exponent-io/jsonpath v0.0.0-20151013193312-d6023ce2651d // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/frankban/quicktest v1.14.5 // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/glaslos/ssdeep v0.3.1 // indirect
	github.com/go-errors/errors v1.4.2 // indirect
	github.com/go-gorp/gorp/v3 v3.0.5 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gobuffalo/here v0.6.0 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/gomodule/redigo v1.8.9 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-intervals v0.0.2 // indirect
	github.com/google/pprof v0.0.0-20230510103437-eeec1cb781c3 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.3 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gorilla/schema v1.2.0 // indirect
	github.com/gosuri/uitable v0.0.4 // indirect
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b // indirect
	github.com/grd/stat v0.0.0-20130623202159-138af3fd5012 // indirect
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/hako/durafmt v0.0.0-20200710122514-c0fb7b4da026 // indirect
	github.com/hashicorp/consul/api v1.12.0 // indirect
	github.com/hashicorp/go-hclog v1.2.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/serf v0.9.7 // indirect
	github.com/hpcloud/tail v1.0.0 // indirect
	github.com/jackc/pgx/v5 v5.2.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jmoiron/sqlx v1.3.5 // indirect
	github.com/juju/ratelimit v1.0.1 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lann/builder v0.0.0-20180802200727-47ae307949d0 // indirect
	github.com/lann/ps v0.0.0-20150810152359-62de8c46ede0 // indirect
	github.com/liamg/iamgo v0.0.9 // indirect
	github.com/liamg/memoryfs v1.6.0 // indirect
	github.com/liamg/tml v0.6.1 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect; indirec
	github.com/linkedin/goavro/v2 v2.9.8 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/manifoldco/promptui v0.9.0 // indirect
	github.com/markbates/pkger v0.17.1 // indirect
	github.com/mattn/go-shellwords v1.0.12 // indirect
	github.com/mattn/go-sqlite3 v1.14.15 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/mistifyio/go-zfs v2.1.2-0.20190413222219-f784269be439+incompatible // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/patternmatcher v0.5.0 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/term v0.0.0-20221205130635-1aeaba878587 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/mtrmac/gpgme v0.1.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/nats-io/nats-server/v2 v2.8.2 // indirect
	github.com/nats-io/nats-streaming-server v0.24.6 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/opencontainers/runtime-spec v1.1.0-rc.1 // indirect
	github.com/opencontainers/runtime-tools v0.9.1-0.20221107090550-2e043c6bd626 // indirect
	github.com/opencontainers/selinux v1.11.0 // indirect
	github.com/ostreedev/ostree-go v0.0.0-20190702140239-759a8c1ac913 // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/peterbourgon/diskv/v3 v3.0.1 // indirect
	github.com/pierrec/lz4 v2.0.5+incompatible // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_golang v1.16.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.3.2 // indirect
	github.com/quic-go/quic-go v0.38.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230126093431-47fa9a501578 // indirect
	github.com/richardlehane/mscfb v1.0.4 // indirect
	github.com/richardlehane/msoleps v1.0.3 // indirect
	github.com/rogpeppe/fastuuid v1.2.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/rookie-ninja/rk-common v1.2.3 // indirect
	github.com/rookie-ninja/rk-logger v1.2.10 // indirect
	github.com/rookie-ninja/rk-query v1.2.10 // indirect
	github.com/rs/xid v1.4.0 // indirect
	github.com/rubenv/sql-migrate v1.3.1 // indirect
	github.com/shabbyrobe/xmlwriter v0.0.0-20200208144257-9fca06d00ffa // indirect
	github.com/skeema/knownhosts v1.1.0 // indirect
	github.com/sony/sonyflake v1.0.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/stefanberger/go-pkcs11uri v0.0.0-20201008174630-78d3cae3a980 // indirect
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	github.com/tchap/go-patricia v2.3.0+incompatible // indirect
	github.com/tchap/go-patricia/v2 v2.3.1 // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/vbauerster/mpb/v7 v7.1.5 // indirect
	github.com/vishvananda/netlink v1.2.1-beta.2 // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xlab/treeprint v1.1.0 // indirect
	github.com/xuri/efp v0.0.0-20220407160117-ad0f7a785be8 // indirect
	github.com/xuri/nfp v0.0.0-20220409054826-5e722a1d9e22 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.etcd.io/etcd/api/v3 v3.5.2 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.2 // indirect
	go.etcd.io/etcd/client/v3 v3.5.1 // indirect
	go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1 // indirect
	go.opentelemetry.io/contrib v1.3.0 // indirect
	go.opentelemetry.io/otel v1.14.0 // indirect
	go.opentelemetry.io/otel/exporters/jaeger v1.4.1 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.3.0 // indirect
	go.opentelemetry.io/otel/sdk v1.14.0 // indirect
	go.opentelemetry.io/otel/trace v1.14.0 // indirect
	go.starlark.net v0.0.0-20200306205701-8dd3e2ee1dd5 // indirect
	go.uber.org/ratelimit v0.2.0 // indirect
	golang.org/x/arch v0.3.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230525234020-1aefcd67740a // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230530153820-e85fd2cbaebc // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	helm.sh/helm/v3 v3.12.1 // indirect
	k8s.io/apiextensions-apiserver v0.27.2 // indirect
	k8s.io/cli-runtime v0.27.2 // indirect
	k8s.io/component-base v0.27.2 // indirect
	k8s.io/kubectl v0.27.2 // indirect
	lukechampine.com/uint128 v1.2.0 // indirect
	modernc.org/cc/v3 v3.40.0 // indirect
	modernc.org/ccgo/v3 v3.16.13 // indirect
	modernc.org/libc v1.22.2 // indirect
	modernc.org/mathutil v1.5.0 // indirect
	modernc.org/memory v1.5.0 // indirect
	modernc.org/opt v0.1.3 // indirect
	modernc.org/sqlite v1.20.3 // indirect
	modernc.org/strutil v1.1.3 // indirect
	modernc.org/token v1.0.1 // indirect
	oras.land/oras-go v1.2.2 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/kustomize/api v0.13.2 // indirect
	sigs.k8s.io/kustomize/kyaml v0.14.1 // indirect
)

require (
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.1452
	github.com/gogo/protobuf v1.3.2
	github.com/smartystreets/goconvey v1.6.4
	go.uber.org/multierr v1.9.0 // indirect
	gorm.io/driver/mysql v1.5.1
	gorm.io/plugin/soft_delete v1.2.0
)

require (
	cloud.google.com/go v0.110.0 // indirect
	cloud.google.com/go/storage v1.28.1 // indirect
	github.com/Azure/azure-sdk-for-go v61.2.0+incompatible // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.24 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.18 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.2 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20211209120228-48547f28849e // indirect
	github.com/BurntSushi/toml v1.3.2 // indirect
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/GoogleCloudPlatform/docker-credential-gcr v1.5.0 // indirect
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/Microsoft/hcsshim v0.10.0-rc.7 // indirect
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20230217124315-7d5c6f04bbb8 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/acomagu/bufpipe v1.0.4 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/apparentlymart/go-cidr v1.1.0 // indirect
	github.com/apparentlymart/go-textseg/v13 v13.0.0 // indirect
	github.com/aquasecurity/cfsec v0.2.2 // indirect
	github.com/aquasecurity/defsec v0.0.37 // indirect
	github.com/aquasecurity/go-dep-parser v0.0.0-20211224170007-df43bca6b6ff // indirect
	github.com/aquasecurity/go-gem-version v0.0.0-20201115065557-8eed6fe000ce // indirect
	github.com/aquasecurity/go-npm-version v0.0.0-20201110091526-0b796d180798 // indirect
	github.com/aquasecurity/go-pep440-version v0.0.0-20210121094942-22b2f8951d46 // indirect
	github.com/aquasecurity/go-version v0.0.0-20210121072130-637058cfe492 // indirect
	github.com/aquasecurity/tfsec v0.63.1 // indirect
	github.com/aws/aws-sdk-go v1.44.122 // indirect
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d // indirect
	github.com/bmatcuk/doublestar v1.3.4 // indirect
	github.com/briandowns/spinner v1.23.0 // indirect
	github.com/caarlos0/env/v6 v6.9.1 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cheggaaa/pb/v3 v3.0.8 // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/containerd/containerd v1.7.0
	github.com/containerd/stargz-snapshotter/estargz v0.13.0 // indirect
	github.com/containerd/typeurl v1.0.2
	github.com/containers/podman/v3 v3.4.6-20220425170000
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/docker/cli v23.0.0-rc.1+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-units v0.5.0 // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.3 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.4.1 // indirect
	github.com/go-git/go-git/v5 v5.6.1 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.1 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-cmp v0.5.9
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0
	github.com/google/wire v0.4.0 // indirect
	github.com/googleapis/gax-go/v2 v2.7.1 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20200217142428-fce0ec30dd00 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.15.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-getter v1.7.1 // indirect
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-retryablehttp v0.7.1 // indirect
	github.com/hashicorp/go-safetemp v1.0.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/go-version v1.6.0
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/hcl/v2 v2.17.0 // indirect
	github.com/huandu/xstrings v1.4.0 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.16.5 // indirect
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f // indirect
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d // indirect
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936 // indirect
	github.com/knqyf263/go-rpmdb v0.0.0-20230723082926-067d98befa60 // indirect
	github.com/knqyf263/nested v0.0.1 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/liamg/jfather v0.0.7 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/masahiro331/go-mvn-version v0.0.0-20210429150710-d3157d602a08 // indirect
	github.com/matryer/is v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/buildkit v0.11.6 // indirect
	github.com/moby/sys/mountinfo v0.6.2
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/nats-io/nkeys v0.3.0 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/open-policy-agent/opa v0.54.0
	github.com/opencontainers/image-spec v1.1.0-rc2.0.20221005185240-3a7f492d3f1b
	github.com/opencontainers/runc v1.1.5 // indirect
	github.com/owenrumney/go-sarif/v2 v2.2.0 // indirect
	github.com/owenrumney/squealer v1.2.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pierrec/lz4/v4 v4.1.17 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rivo/uniseg v0.3.4 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/saracen/walker v0.0.0-20191201085201-324a081bae7e
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/smartystreets/assertions v1.2.0 // indirect
	github.com/spf13/afero v1.8.2 // indirect
	github.com/spf13/cast v1.5.0
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/tmccombs/hcl2json v0.3.4-0.20220219194047-6a716d5407ef // indirect
	github.com/twitchtv/twirp v8.1.1+incompatible // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	github.com/zclconf/go-cty v1.13.2 // indirect
	github.com/zclconf/go-cty-yaml v1.0.3 // indirect
	go.etcd.io/bbolt v1.3.7 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/crypto v0.10.0 // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/oauth2 v0.7.0 // indirect
	golang.org/x/term v0.9.0 // indirect
	golang.org/x/text v0.10.0 // indirect
	golang.org/x/tools v0.9.1 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2
	gomodules.xyz/orderedmap v0.1.0 // indirect
	google.golang.org/api v0.114.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230525234025-438c736192d0 // indirect
	gopkg.in/cheggaaa/pb.v1 v1.0.28 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.66.4 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/kube-openapi v0.0.0-20230501164219-8b0f38b5fd1f // indirect
	k8s.io/utils v0.0.0-20230505201702-9f6742963106
	scm.tensorsecurity.cn/tensorsecurity-rd/fanal v1.1.4
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0
)

replace (
	github.com/containernetworking/cni => github.com/containernetworking/cni v0.8.1
	github.com/containers/podman/v3 => scm.tensorsecurity.cn/tensorsecurity-rd/podman/v3 v3.4.6-20220425170000
	//github.com/opencontainers/image-spec => github.com/opencontainers/image-spec v1.0.2-0.20210819154149-5ad6f50d6283
	gitlab.com/security-rd/go-pkg => scm.tensorsecurity.cn/tensorsecurity-rd/go-pkg v0.2.88
	go.opentelemetry.io/otel/metric => go.opentelemetry.io/otel/metric v0.35.0
	helm.sh/helm/v3 => helm.sh/helm/v3 v3.11.1
	k8s.io/api => k8s.io/kubernetes/staging/src/k8s.io/api v0.0.0-20220503133649-4ce5a8954017
	k8s.io/apiextensions-apiserver => k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver v0.0.0-20220503133649-4ce5a8954017
	k8s.io/apimachinery => k8s.io/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20220503133649-4ce5a8954017
	k8s.io/apiserver => k8s.io/kubernetes/staging/src/k8s.io/apiserver v0.0.0-20220503133649-4ce5a8954017
	k8s.io/cli-runtime => k8s.io/kubernetes/staging/src/k8s.io/cli-runtime v0.0.0-20220503133649-4ce5a8954017
	k8s.io/client-go => k8s.io/kubernetes/staging/src/k8s.io/client-go v0.0.0-20220503133649-4ce5a8954017
	k8s.io/cloud-provider => k8s.io/kubernetes/staging/src/k8s.io/cloud-provider v0.0.0-20220503133649-4ce5a8954017
	k8s.io/cluster-bootstrap => k8s.io/kubernetes/staging/src/k8s.io/cluster-bootstrap v0.0.0-20220503133649-4ce5a8954017
	k8s.io/code-generator => k8s.io/kubernetes/staging/src/k8s.io/code-generator v0.0.0-20220503133649-4ce5a8954017
	k8s.io/component-base => k8s.io/kubernetes/staging/src/k8s.io/component-base v0.0.0-20220503133649-4ce5a8954017
	k8s.io/component-helpers => k8s.io/kubernetes/staging/src/k8s.io/component-helpers v0.0.0-20220503133649-4ce5a8954017
	k8s.io/controller-manager => k8s.io/kubernetes/staging/src/k8s.io/controller-manager v0.0.0-20220503133649-4ce5a8954017
	k8s.io/cri-api => k8s.io/kubernetes/staging/src/k8s.io/cri-api v0.0.0-20220503133649-4ce5a8954017
	k8s.io/csi-translation-lib => k8s.io/kubernetes/staging/src/k8s.io/csi-translation-lib v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kube-aggregator => k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kube-controller-manager => k8s.io/kubernetes/staging/src/k8s.io/kube-controller-manager v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kube-proxy => k8s.io/kubernetes/staging/src/k8s.io/kube-proxy v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kube-scheduler => k8s.io/kubernetes/staging/src/k8s.io/kube-scheduler v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kubectl => k8s.io/kubectl v0.26.2
	k8s.io/kubelet => k8s.io/kubernetes/staging/src/k8s.io/kubelet v0.0.0-20220503133649-4ce5a8954017
	k8s.io/legacy-cloud-providers => k8s.io/kubernetes/staging/src/k8s.io/legacy-cloud-providers v0.0.0-20220503133649-4ce5a8954017
	k8s.io/metrics => k8s.io/kubernetes/staging/src/k8s.io/metrics v0.0.0-20220503133649-4ce5a8954017
	k8s.io/mount-utils => k8s.io/kubernetes/staging/src/k8s.io/mount-utils v0.0.0-20220503133649-4ce5a8954017
	k8s.io/pod-security-admission => k8s.io/kubernetes/staging/src/k8s.io/pod-security-admission v0.0.0-20220503133649-4ce5a8954017
	k8s.io/sample-apiserver => k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver v0.0.0-20220503133649-4ce5a8954017
	oras.land/oras-go => oras.land/oras-go v1.1.1
	sigs.k8s.io/kustomize/api => sigs.k8s.io/kustomize/api v0.12.1
	sigs.k8s.io/kustomize/kyaml => sigs.k8s.io/kustomize/kyaml v0.13.9
)
