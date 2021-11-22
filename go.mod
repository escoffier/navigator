module gitlab.com/piccolo_su/vegeta

go 1.17

require (
	github.com/PuerkitoBio/goquery v1.6.0
	github.com/ReneKroon/ttlcache/v2 v2.9.0
	github.com/agnivade/levenshtein v1.1.1
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/armon/go-metrics v0.3.10 // indirect
	github.com/avast/retry-go v3.0.0+incompatible
	github.com/badoux/checkmail v1.2.1
	github.com/boltdb/bolt v1.3.1
	github.com/dchest/captcha v0.0.0-20200903113550-03f5f0333e1f
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v20.10.9+incompatible
	github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c // indirect
	github.com/elazarl/goproxy v0.0.0-20201021153353-00ad82a08272 // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible
	github.com/facebookarchive/freeport v0.0.0-20150612182905-d4adf43b75b9
	github.com/falcosecurity/client-go v0.4.0
	github.com/fatih/color v1.13.0 // indirect
	github.com/florianl/go-conntrack v0.2.0 //conntrack
	github.com/fsnotify/fsnotify v1.5.1
	github.com/gin-gonic/gin v1.7.4
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/jwtauth v4.0.4+incompatible
	github.com/go-openapi/spec v0.19.9 // indirect
	github.com/go-openapi/swag v0.19.9 // indirect
	github.com/go-playground/validator/v10 v10.9.0 // indirect
	github.com/go-redis/redis/v8 v8.11.4
	github.com/gofrs/uuid v4.0.0+incompatible
	github.com/golang-migrate/migrate/v4 v4.14.1
	github.com/golang/gddo v0.0.0-20190904175337-72a348e765d2
	github.com/golang/protobuf v1.5.2
	github.com/google/go-containerregistry v0.1.2 //ct
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/heroku/docker-registry-client v0.0.0-20190909225348-afc9e1acc3d5
	github.com/huaweicloud/huaweicloud-sdk-go-v3 v0.0.59
	github.com/json-iterator/go v1.1.12
	github.com/lib/pq v1.10.4
	github.com/mattn/go-colorable v0.1.11 // indirect
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
	github.com/mileusna/crontab v1.2.0
	github.com/minio/highwayhash v1.0.2 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mozilla/tls-observatory v0.0.0-20200317151703-4fa42e1c2dee
	github.com/nats-io/nats-server/v2 v2.6.3 // indirect
	github.com/nats-io/nats-streaming-server v0.23.0 // indirect
	github.com/nats-io/nats.go v1.13.1-0.20211018182449-f2416a8b1483
	github.com/nats-io/stan.go v0.10.2
	github.com/novln/docker-parser v1.0.0
	github.com/oceanicdev/chi-param v1.1.0
	github.com/oleiade/lane v1.0.1
	github.com/olekukonko/tablewriter v0.0.5 //ct
	github.com/olivere/elastic/v7 v7.0.29
	github.com/opencontainers/go-digest v1.0.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/quay/clair/v2 v2.1.7
	github.com/robfig/cron/v3 v3.0.1
	github.com/rogpeppe/go-internal v1.8.0
	github.com/rs/zerolog v1.26.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.7.0
	github.com/swaggo/files v0.0.0-20190704085106-630677cd5c14
	github.com/swaggo/gin-swagger v1.2.0
	github.com/swaggo/swag v1.6.7
	github.com/tealeg/xlsx v1.0.5
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	github.com/tomogoma/generator v0.0.0-20171014125632-4398aab4dd41 // indirect
	github.com/tomogoma/go-api-guard v0.0.0-20180312041446-a2bad766ec64
	github.com/tomogoma/go-typed-errors v0.0.0-20181222204503-0532faf740be
	github.com/urfave/cli/v2 v2.3.0
	github.com/yeka/zip v0.0.0-20180914125537-d046722c6feb
	gitlab.com/security-rd/go-pkg v0.1.6
	go.mongodb.org/mongo-driver v1.7.4
	go.uber.org/atomic v1.9.0
	go.uber.org/automaxprocs v1.4.0
	go.uber.org/zap v1.19.1
	golang.org/x/crypto v0.0.0-20211117183948-ae814b36b871 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20211117180635-dee7805ff2e1
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac // indirect
	google.golang.org/genproto v0.0.0-20211016002631-37fc39342514 // indirect
	google.golang.org/grpc v1.41.0
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/datatypes v1.0.3
	gorm.io/driver/postgres v1.2.2
	gorm.io/gorm v1.22.3
	k8s.io/api v0.19.12
	k8s.io/apimachinery v0.19.12
	k8s.io/apiserver v0.19.12
	k8s.io/client-go v0.19.12
	scm.tensorsecurity.cn/tensorsecurity-rd/cloudwalker v0.0.4
	scm.tensorsecurity.cn/tensorsecurity-rd/trivy v0.0.0-20211013023834-4d8cd20c2071
)

require (
	github.com/go-ldap/ldap/v3 v3.4.1
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
)

require (
	github.com/elastic/go-libaudit/v2 v2.2.0
	github.com/ghodss/yaml v1.0.0
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0
	github.com/gobwas/glob v0.2.3
	gomodules.xyz/jsonpatch/v3 v3.0.1
	google.golang.org/protobuf v1.27.1
	layeh.com/radius v0.0.0-20210819152912-ad72663a72ab
)

require (
	github.com/go-redsync/redsync/v4 v4.3.0
	github.com/gogo/protobuf v1.3.2
	github.com/hashicorp/raft v1.3.2 // indirect
	github.com/smartystreets/goconvey v1.6.4
	go.uber.org/multierr v1.7.0 // indirect
	gorm.io/plugin/soft_delete v1.0.4
)

require (
	cloud.google.com/go v0.65.0 // indirect
	cloud.google.com/go/storage v1.10.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20200615164410-66371956d46c // indirect
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/CyrusF/go-bayesian v0.0.0-20180928040635-c6aa877814bd // indirect
	github.com/CyrusF/libsvm-go v0.0.0-20180928035651-2210b124fd3d // indirect
	github.com/GoogleCloudPlatform/docker-credential-gcr v1.5.0 // indirect
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible // indirect
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/Microsoft/hcsshim v0.8.14 // indirect
	github.com/NYTimes/gziphandler v0.0.0-20170623195520-56545f4a5d46 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/VividCortex/ewma v1.1.1 // indirect
	github.com/agext/levenshtein v1.2.2 // indirect
	github.com/andybalholm/cascadia v1.1.0 // indirect
	github.com/apparentlymart/go-cidr v1.1.0 // indirect
	github.com/apparentlymart/go-textseg/v13 v13.0.0 // indirect
	github.com/aquasecurity/go-dep-parser v0.0.0-20210520015931-0dd56983cc62 // indirect
	github.com/aquasecurity/go-gem-version v0.0.0-20201115065557-8eed6fe000ce // indirect
	github.com/aquasecurity/go-npm-version v0.0.0-20201110091526-0b796d180798 // indirect
	github.com/aquasecurity/go-pep440-version v0.0.0-20210121094942-22b2f8951d46 // indirect
	github.com/aquasecurity/go-version v0.0.0-20210121072130-637058cfe492 // indirect
	github.com/aquasecurity/trivy-db v0.0.0-20210531102723-aaab62dec6ee // indirect
	github.com/aquasecurity/vuln-list-update v0.0.0-20191016075347-3d158c2bf9a2 // indirect
	github.com/aws/aws-sdk-go v1.40.43 // indirect
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d // indirect
	github.com/bmatcuk/doublestar v1.3.4 // indirect
	github.com/briandowns/spinner v1.12.0 // indirect
	github.com/caarlos0/env/v6 v6.0.0 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cheggaaa/pb/v3 v3.0.3 // indirect
	github.com/containerd/cgroups v0.0.0-20210114181951-8a68de567b68 // indirect
	github.com/containerd/containerd v1.4.11 // indirect
	github.com/containerd/typeurl v1.0.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/deckarep/golang-set v1.7.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/docker/cli v20.10.0-beta1.0.20201029214301-1d20b15adc38+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.6.3 // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/glaslos/ssdeep v0.3.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.1 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.0.0 // indirect
	github.com/go-git/go-git/v5 v5.0.0 // indirect
	github.com/go-logr/logr v0.2.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.3 // indirect
	github.com/go-openapi/jsonreference v0.19.4 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-restruct/restruct v0.0.0-20191227155143-5734170a48a1 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/google/go-github/v33 v33.0.0 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/google/uuid v1.2.0 // indirect
	github.com/google/wire v0.4.0 // indirect
	github.com/googleapis/gax-go/v2 v2.0.5 // indirect
	github.com/googleapis/gnostic v0.4.1 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20200217142428-fce0ec30dd00 // indirect
	github.com/grd/stat v0.0.0-20130623202159-138af3fd5012 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/go-getter v1.5.2 // indirect
	github.com/hashicorp/go-hclog v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.8 // indirect
	github.com/hashicorp/go-safetemp v1.0.0 // indirect
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/hashicorp/go-version v1.3.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/hcl/v2 v2.10.0 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.9 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.10.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.2.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.9.0 // indirect
	github.com/jackc/pgx/v4 v4.14.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/jstemmer/go-junit-report v0.9.1 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/kevinburke/ssh_config v0.0.0-20190725054713-01f96b0aa0cd // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f // indirect
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d // indirect
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936 // indirect
	github.com/knqyf263/go-rpmdb v0.0.0-20201215100354-a9e3110d8ee1 // indirect
	github.com/knqyf263/nested v0.0.1 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/masahiro331/go-mvn-version v0.0.0-20210429150710-d3157d602a08 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-runewidth v0.0.12 // indirect
	github.com/mdlayher/netlink v1.1.0 // indirect
	github.com/mitchellh/copystructure v1.1.1 // indirect
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/moby/buildkit v0.8.1 // indirect
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/moby/sys/mountinfo v0.4.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/nats-io/nkeys v0.3.0 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/open-policy-agent/opa v0.25.2 // indirect
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6 // indirect
	github.com/opencontainers/runc v1.0.0-rc92 // indirect
	github.com/parnurzeal/gorequest v0.2.16 // indirect
	github.com/pelletier/go-toml v1.8.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/saracen/walker v0.0.0-20191201085201-324a081bae7e // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/smartystreets/assertions v1.2.0 // indirect
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/stretchr/objx v0.3.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/tfsec/tfsec v0.40.8-0.20210702100641-956c4f18a1b8 // indirect
	github.com/tmccombs/hcl2json v0.3.1 // indirect
	github.com/twitchtv/twirp v8.1.0+incompatible // indirect
	github.com/ugorji/go/codec v1.2.6 // indirect
	github.com/ulikunitz/xz v0.5.8 // indirect
	github.com/wasmerio/go-ext-wasm v0.3.1 // indirect
	github.com/xanzy/ssh-agent v0.2.1 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.0.2 // indirect
	github.com/xdg-go/stringprep v1.0.2 // indirect
	github.com/yashtewari/glob-intersection v0.0.0-20180916065949-5c77d914dd0b // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	github.com/zclconf/go-cty v1.8.4 // indirect
	github.com/zclconf/go-cty-yaml v1.0.2 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/oauth2 v0.0.0-20201208152858-08078c50e5b5 // indirect
	golang.org/x/term v0.0.0-20201210144234-2321bbc49cbf // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/tools v0.1.7 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gomodules.xyz/orderedmap v0.1.0 // indirect
	google.golang.org/api v0.30.0 // indirect
	google.golang.org/appengine v1.6.6 // indirect
	gopkg.in/cheggaaa/pb.v1 v1.0.28 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.56.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	k8s.io/klog/v2 v2.2.0 // indirect
	k8s.io/kube-openapi v0.0.0-20200805222855-6aeccd4b50c6 // indirect
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920 // indirect
	moul.io/http2curl v1.0.0 // indirect
	scm.tensorsecurity.cn/tensorsecurity-rd/fanal v0.0.0-20211012111105-ed1487f4c8a5 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.0.3 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)

replace gitlab.com/security-rd/go-pkg => scm.tensorsecurity.cn/tensorsecurity-rd/go-pkg v0.1.6
