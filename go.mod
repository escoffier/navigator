module gitlab.com/piccolo_su/vegeta

go 1.19

require (
	github.com/PuerkitoBio/goquery v1.8.0
	github.com/agnivade/levenshtein v1.1.1
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/avast/retry-go v3.0.0+incompatible
	github.com/badoux/checkmail v1.2.1
	github.com/boltdb/bolt v1.3.1
	github.com/dchest/captcha v1.0.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.8.1+incompatible
	github.com/docker/docker v20.10.22+incompatible
	github.com/elazarl/goproxy v0.0.0-20220901064549-fbd10ff4f5a1 // indirect
	github.com/emicklei/go-restful v2.16.0+incompatible
	github.com/facebookarchive/freeport v0.0.0-20150612182905-d4adf43b75b9
	github.com/falcosecurity/client-go v0.5.0
	github.com/fatih/color v1.13.0 // indirect
	github.com/florianl/go-conntrack v0.3.0 //conntrack
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gin-gonic/gin v1.8.2
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/jwtauth v4.0.4+incompatible
	github.com/go-openapi/spec v0.19.9 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/go-playground/validator/v10 v10.11.1 // indirect
	github.com/go-redis/redis/v8 v8.11.5
	github.com/gofrs/uuid v4.3.1+incompatible
	github.com/golang-migrate/migrate/v4 v4.14.1
	github.com/golang/gddo v0.0.0-20210115222349-20d68f94ee1f
	github.com/google/go-containerregistry v0.7.1-0.20211214010025-a65b7844a475 //ct
	github.com/heroku/docker-registry-client v0.0.0-20211012143308-9463674c8930
	github.com/huaweicloud/huaweicloud-sdk-go-v3 v0.0.59
	github.com/json-iterator/go v1.1.12
	github.com/lib/pq v1.10.7
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
	github.com/mileusna/crontab v1.2.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mozilla/tls-observatory v0.0.0-20210609171429-7bc42856d2e5
	github.com/nats-io/nats.go v1.15.0
	github.com/nats-io/stan.go v0.10.2
	github.com/novln/docker-parser v1.0.0
	github.com/oceanicdev/chi-param v1.1.0
	github.com/oleiade/lane v1.0.1
	github.com/olekukonko/tablewriter v0.0.5 // indirect; ct
	github.com/olivere/elastic/v7 v7.0.32
	github.com/opencontainers/go-digest v1.0.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/quay/clair/v2 v2.1.7
	github.com/robfig/cron/v3 v3.0.1
	github.com/rs/zerolog v1.28.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.9.0
	github.com/spf13/cobra v1.6.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.11.0
	github.com/stretchr/testify v1.8.1
	github.com/swaggo/swag v1.6.7
	github.com/tealeg/xlsx v1.0.5
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	github.com/tomogoma/generator v0.0.0-20171014125632-4398aab4dd41 // indirect
	github.com/tomogoma/go-api-guard v0.0.0-20180312041446-a2bad766ec64
	github.com/tomogoma/go-typed-errors v0.0.0-20181222204503-0532faf740be
	github.com/urfave/cli/v2 v2.3.0
	github.com/yeka/zip v0.0.0-20180914125537-d046722c6feb
	gitlab.com/security-rd/go-pkg v0.2.63
	go.mongodb.org/mongo-driver v1.8.2
	go.uber.org/atomic v1.10.0
	go.uber.org/automaxprocs v1.5.1
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/net v0.5.0
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.4.0
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8
	google.golang.org/grpc v1.51.0
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/datatypes v1.0.3
	gorm.io/driver/postgres v1.4.5
	gorm.io/gorm v1.24.3
	k8s.io/api v0.20.15
	k8s.io/apimachinery v0.20.15
	k8s.io/apiserver v0.20.15
	k8s.io/client-go v0.20.15
	scm.tensorsecurity.cn/tensorsecurity-rd/cloudwalker v0.0.5
	scm.tensorsecurity.cn/tensorsecurity-rd/falcosider v0.1.5
	scm.tensorsecurity.cn/tensorsecurity-rd/trivy v0.19.3-0.20221223094108-043b8936a019
)

require github.com/go-ldap/ldap/v3 v3.4.1

require (
	github.com/afex/hystrix-go v0.0.0-20180502004556-fa1af6a1f4f5
	github.com/ahmetb/go-linq/v3 v3.2.0
	github.com/elastic/go-libaudit/v2 v2.2.0
	github.com/ghodss/yaml v1.0.0
	github.com/gin-contrib/pprof v1.4.0
	github.com/go-sql-driver/mysql v1.7.0
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0
	github.com/gobwas/glob v0.2.3
	github.com/golang/protobuf v1.5.2
	github.com/gorilla/handlers v1.4.2
	github.com/imroc/req/v3 v3.23.0
	github.com/jarcoal/httpmock v1.2.0
	github.com/jellydator/ttlcache/v3 v3.0.0
	github.com/rookie-ninja/rk-entry v1.0.11
	github.com/rookie-ninja/rk-gin v1.2.22
	github.com/segmentio/kafka-go v0.4.38
	github.com/shopspring/decimal v1.2.0
	github.com/sony/gobreaker v0.5.0
	github.com/xuri/excelize/v2 v2.6.0
	gomodules.xyz/jsonpatch/v3 v3.0.1
	google.golang.org/protobuf v1.28.1
	gorm.io/driver/sqlite v1.4.3
	k8s.io/cri-api v0.24.0
	k8s.io/klog/v2 v2.60.1
	k8s.io/kubernetes v1.24.0
	layeh.com/radius v0.0.0-20210819152912-ad72663a72ab
	scm.tensorsecurity.cn/tensorsecurity-rd/api v0.2.2
)

require (
	cloud.google.com/go/compute v1.13.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.1 // indirect
	cloud.google.com/go/iam v0.8.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Shopify/sarama v1.37.2 // indirect
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d // indirect
	github.com/andres-erbsen/clock v0.0.0-20160526145045-9e14626cd129 // indirect
	github.com/armon/go-metrics v0.3.11 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/cheekybits/genny v1.0.0 // indirect
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	github.com/containernetworking/cni v0.8.1 // indirect
	github.com/containernetworking/plugins v0.9.1 // indirect
	github.com/containers/buildah v1.23.1 // indirect
	github.com/containers/common v0.44.5 // indirect
	github.com/containers/image/v5 v5.17.0 // indirect
	github.com/containers/libtrust v0.0.0-20190913040956-14b96171aa3b // indirect
	github.com/containers/ocicrypt v1.1.2 // indirect
	github.com/containers/psgo v1.7.1 // indirect
	github.com/containers/storage v1.37.1 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd/v22 v22.3.3-0.20220203105225-a9a7ef127534 // indirect
	github.com/cri-o/ocicni v0.2.1-0.20210621164014-d0acc7862283 // indirect
	github.com/cyphar/filepath-securejoin v0.2.3 // indirect
	github.com/disiqueira/gotree/v3 v3.0.2 // indirect
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/eapache/go-resiliency v1.3.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20180814174437-776d5712da21 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gobuffalo/here v0.6.0 // indirect
	github.com/goccy/go-json v0.10.0 // indirect
	github.com/godbus/dbus/v5 v5.0.6 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-intervals v0.0.2 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.0 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gorilla/schema v1.2.0 // indirect
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b // indirect
	github.com/hako/durafmt v0.0.0-20200710122514-c0fb7b4da026 // indirect
	github.com/hashicorp/consul/api v1.12.0 // indirect
	github.com/hashicorp/go-hclog v1.2.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/serf v0.9.7 // indirect
	github.com/hpcloud/tail v1.0.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.3 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jinzhu/copier v0.3.2 // indirect
	github.com/juju/ratelimit v1.0.1 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/lucas-clemente/quic-go v0.28.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/manifoldco/promptui v0.9.0 // indirect
	github.com/markbates/pkger v0.17.1 // indirect
	github.com/marten-seemann/qpack v0.2.1 // indirect
	github.com/marten-seemann/qtls-go1-16 v0.1.5 // indirect
	github.com/marten-seemann/qtls-go1-17 v0.1.2 // indirect
	github.com/marten-seemann/qtls-go1-18 v0.1.2 // indirect
	github.com/marten-seemann/qtls-go1-19 v0.1.0-beta.1 // indirect
	github.com/mattn/go-shellwords v1.0.12 // indirect
	github.com/mattn/go-sqlite3 v1.14.15 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/mistifyio/go-zfs v2.1.2-0.20190413222219-f784269be439+incompatible // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/mtrmac/gpgme v0.1.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/nats-io/nats-server/v2 v2.8.2 // indirect
	github.com/nats-io/nats-streaming-server v0.24.6 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417 // indirect
	github.com/opencontainers/runtime-tools v0.9.0 // indirect
	github.com/opencontainers/selinux v1.10.0 // indirect
	github.com/ostreedev/ostree-go v0.0.0-20190702140239-759a8c1ac913 // indirect
	github.com/pelletier/go-toml/v2 v2.0.6 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_golang v1.12.1 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/richardlehane/mscfb v1.0.4 // indirect
	github.com/richardlehane/msoleps v1.0.3 // indirect
	github.com/rookie-ninja/rk-common v1.2.3 // indirect
	github.com/rookie-ninja/rk-logger v1.2.10 // indirect
	github.com/rookie-ninja/rk-query v1.2.10 // indirect
	github.com/rs/xid v1.4.0 // indirect
	github.com/shirou/gopsutil/v3 v3.22.10 // indirect
	github.com/sony/sonyflake v1.0.0 // indirect
	github.com/stefanberger/go-pkcs11uri v0.0.0-20201008174630-78d3cae3a980 // indirect
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	github.com/tchap/go-patricia v2.3.0+incompatible // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/vbauerster/mpb/v7 v7.1.5 // indirect
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852 // indirect
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xuri/efp v0.0.0-20220407160117-ad0f7a785be8 // indirect
	github.com/xuri/nfp v0.0.0-20220409054826-5e722a1d9e22 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.etcd.io/etcd/api/v3 v3.5.2 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.2 // indirect
	go.etcd.io/etcd/client/v3 v3.5.1 // indirect
	go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1 // indirect
	go.opentelemetry.io/contrib v1.3.0 // indirect
	go.opentelemetry.io/otel v1.5.0 // indirect
	go.opentelemetry.io/otel/exporters/jaeger v1.3.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.3.0 // indirect
	go.opentelemetry.io/otel/sdk v1.3.0 // indirect
	go.opentelemetry.io/otel/trace v1.5.0 // indirect
	go.uber.org/ratelimit v0.2.0 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	k8s.io/component-base v0.20.6 // indirect
	sigs.k8s.io/json v0.0.0-20211208200746-9f7c6b3444d2 // indirect
)

require (
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.1452
	github.com/go-redsync/redsync/v4 v4.3.0
	github.com/gogo/protobuf v1.3.2
	github.com/smartystreets/goconvey v1.6.4
	go.uber.org/multierr v1.9.0 // indirect
	gorm.io/driver/mysql v1.4.5
	gorm.io/plugin/soft_delete v1.2.0
)

require (
	cloud.google.com/go v0.105.0 // indirect
	cloud.google.com/go/storage v1.27.0 // indirect
	github.com/Azure/azure-sdk-for-go v61.2.0+incompatible // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.24 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.18 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.2 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20211209120228-48547f28849e // indirect
	github.com/BurntSushi/toml v1.0.0 // indirect
	github.com/CyrusF/go-bayesian v0.0.0-20180928040635-c6aa877814bd // indirect
	github.com/CyrusF/libsvm-go v0.0.0-20180928035651-2210b124fd3d // indirect
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/GoogleCloudPlatform/docker-credential-gcr v1.5.0 // indirect
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/Microsoft/hcsshim v0.9.2 // indirect
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20210428141323-04723f9f07d7 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/acomagu/bufpipe v1.0.3 // indirect
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
	github.com/aquasecurity/trivy-db v0.0.0-20220130223604-df65ebde46f4
	github.com/aws/aws-sdk-go v1.44.73 // indirect
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d // indirect
	github.com/bmatcuk/doublestar v1.3.4 // indirect
	github.com/briandowns/spinner v1.12.0 // indirect
	github.com/caarlos0/env/v6 v6.9.1 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cheggaaa/pb/v3 v3.0.8 // indirect
	github.com/containerd/cgroups v1.0.4 // indirect
	github.com/containerd/containerd v1.5.16 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.12.1 // indirect
	github.com/containerd/typeurl v1.0.2 // indirect
	github.com/containers/podman/v3 v3.4.6-20220425170000
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/docker/cli v20.10.17+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/glaslos/ssdeep v0.3.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.3 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.3.1 // indirect
	github.com/go-git/go-git/v5 v5.4.2 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-restruct/restruct v0.0.0-20191227155143-5734170a48a1 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0
	github.com/google/wire v0.4.0 // indirect
	github.com/googleapis/gax-go/v2 v2.7.0 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20200217142428-fce0ec30dd00 // indirect
	github.com/grd/stat v0.0.0-20130623202159-138af3fd5012 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.11.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-getter v1.6.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.0 // indirect
	github.com/hashicorp/go-safetemp v1.0.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/hcl/v2 v2.11.1 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.13.0 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.1 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.13.0 // indirect
	github.com/jackc/pgx/v4 v4.17.2 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/kevinburke/ssh_config v0.0.0-20201106050909-4977a11b4351 // indirect
	github.com/klauspost/compress v1.15.14 // indirect
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f // indirect
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d // indirect
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936 // indirect
	github.com/knqyf263/go-rpmdb v0.0.0-20211216113947-1369b2ee40b7 // indirect
	github.com/knqyf263/nested v0.0.1 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/liamg/jfather v0.0.2 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/masahiro331/go-mvn-version v0.0.0-20210429150710-d3157d602a08 // indirect
	github.com/matryer/is v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mdlayher/netlink v1.7.1 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/mitchellh/copystructure v1.1.1 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/moby/buildkit v0.9.3 // indirect
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/moby/sys/mountinfo v0.6.0
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/nats-io/nkeys v0.3.0 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/open-policy-agent/opa v0.36.1 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc2 // indirect
	github.com/opencontainers/runc v1.1.1 // indirect
	github.com/owenrumney/go-sarif/v2 v2.1.1 // indirect
	github.com/owenrumney/squealer v0.2.28 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.17 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rivo/uniseg v0.3.4 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/saracen/walker v0.0.0-20191201085201-324a081bae7e
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/smartystreets/assertions v1.2.0 // indirect
	github.com/spf13/afero v1.8.2 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/tmccombs/hcl2json v0.3.4-0.20220219194047-6a716d5407ef // indirect
	github.com/twitchtv/twirp v8.1.1+incompatible // indirect
	github.com/ugorji/go/codec v1.2.8 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	github.com/xanzy/ssh-agent v0.3.0 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.1 // indirect
	github.com/xdg-go/stringprep v1.0.3 // indirect
	github.com/xdg/scram v1.0.5 // indirect
	github.com/xdg/stringprep v1.0.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.0.0-20180916065949-5c77d914dd0b // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	github.com/zclconf/go-cty v1.10.0 // indirect
	github.com/zclconf/go-cty-yaml v1.0.2 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/crypto v0.5.0 // indirect
	golang.org/x/mod v0.6.0 // indirect
	golang.org/x/oauth2 v0.1.0 // indirect
	golang.org/x/term v0.4.0 // indirect
	golang.org/x/text v0.6.0 // indirect
	golang.org/x/tools v0.1.12 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	gomodules.xyz/orderedmap v0.1.0 // indirect
	google.golang.org/api v0.103.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230106154932-a12b697841d9 // indirect
	gopkg.in/cheggaaa/pb.v1 v1.0.28 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.66.4 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/kube-openapi v0.0.0-20220328201542-3ee0da9b0b42 // indirect
	k8s.io/utils v0.0.0-20220210201930-3a6ce19ff2f9 // indirect
	scm.tensorsecurity.cn/tensorsecurity-rd/fanal v0.0.0-20220415061508-baf9465b55a7
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

replace (
	github.com/containers/podman/v3 => scm.tensorsecurity.cn/tensorsecurity-rd/podman/v3 v3.4.6-20220425170000
	github.com/opencontainers/image-spec => github.com/opencontainers/image-spec v1.0.2-0.20210819154149-5ad6f50d6283
	gitlab.com/security-rd/go-pkg => scm.tensorsecurity.cn/tensorsecurity-rd/go-pkg v0.2.64
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
	k8s.io/kubectl => k8s.io/kubernetes/staging/src/k8s.io/kubectl v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kubelet => k8s.io/kubernetes/staging/src/k8s.io/kubelet v0.0.0-20220503133649-4ce5a8954017
	k8s.io/legacy-cloud-providers => k8s.io/kubernetes/staging/src/k8s.io/legacy-cloud-providers v0.0.0-20220503133649-4ce5a8954017
	k8s.io/metrics => k8s.io/kubernetes/staging/src/k8s.io/metrics v0.0.0-20220503133649-4ce5a8954017
	k8s.io/mount-utils => k8s.io/kubernetes/staging/src/k8s.io/mount-utils v0.0.0-20220503133649-4ce5a8954017
	k8s.io/pod-security-admission => k8s.io/kubernetes/staging/src/k8s.io/pod-security-admission v0.0.0-20220503133649-4ce5a8954017
	k8s.io/sample-apiserver => k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver v0.0.0-20220503133649-4ce5a8954017
)
