# create database  ivan;

use ivan;

create table if not exists ivan_export_task
(
    id           int unsigned auto_increment
        primary key,
    task_type    varchar(100) default ''                not null,
    execute_type varchar(50)  default ''                null,
    parameter    longtext                               null,
    file_path    text                                   null,
    creator      varchar(200) default ''                not null,
    start_at     bigint       default 0                 not null,
    finish_at    bigint       default 0                 not null,
    err_msg      longtext                               null,
    created_at   timestamp    default CURRENT_TIMESTAMP not null,
    updated_at   timestamp    default CURRENT_TIMESTAMP not null,
    lang         varchar(100) default ''                not null,
    index idx_created_at (created_at),
    index idx_execute_type (execute_type)
);

CREATE TABLE IF NOT EXISTS `ivan_export_vuln_image`
(
    `id`          bigint unsigned  NOT NULL AUTO_INCREMENT,
    `task_id`     bigint unsigned  NOT NULL DEFAULT 0,
    `unique_vuln` bigint unsigned  NOT NULL DEFAULT 0,
    `severity`    tinyint unsigned NOT NULL DEFAULT 0,
    `can_fixed`   bool             NOT NULL DEFAULT false,
    `images`      longtext,
    PRIMARY KEY (`id`),
    UNIQUE KEY `task_vuln` (`task_id`, `unique_vuln`),
    key `task_vuln_severity` (`task_id`, `severity`, `unique_vuln`)
) ENGINE = InnoDB
  CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `ivan_export_task_image`
(
    `id`         bigint unsigned NOT NULL AUTO_INCREMENT,
    `task_id`    bigint unsigned not null default 0,
    `image_id`   bigint unsigned not null default 0,
    `image_name` varchar(200)    not null default '',
    PRIMARY KEY (`id`),
    unique key task_image (task_id, image_id)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `ivan_export_html_prepare`
(
    `id`        bigint unsigned NOT NULL AUTO_INCREMENT,
    `task_id`   bigint unsigned not null default 0,
    `data_type` tinyint         not null default 0,
    `data`      longtext        not null,
    PRIMARY KEY (`id`),
    unique key task_id (task_id, data_type)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;

create table if not exists ivan_detect_policy_snapshot
(
    id              bigint unsigned auto_increment,
    policy_id       bigint unsigned not null default 0,
    unique_id       bigint unsigned not null default 0,
    security_policy longtext        not null,
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    unique index unq_unique_id (unique_id)
);

create table if not exists ivan_image_exist_reg_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_base_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_trusted_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_scan_online_vuln
(
    id                   bigint unsigned auto_increment,
    unique_id            bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    pkg_unique_id        bigint unsigned not null default 0,
    `name`               varchar(100)    not null default '',
    pkg_name             varchar(100)    not null default '',
    src_name             varchar(300)    not null default '',
    src_version          varchar(300)    not null default '',
    pkg_version          varchar(100)    not null default '',
    cnnvd_name           varchar(300)    not null default '',
    cnnvd_fix_suggestion text            not null,
    description_en       text            not null,
    description_zh       text            not null,
    pkg_type             varchar(50)     not null default '',
    `references`         longtext        not null,
    `class`              varchar(200)    not null default '',
    `cvss`               longtext        not null,
    `ced_ids`            text            not null,
    `title`              text            not null,
    `cnvd_title`         text            not null,
    publish_at           bigint unsigned not null default 0,
    modify_at            bigint unsigned not null default 0,
    severity             bigint unsigned not null default 0,
    check_sum            bigint unsigned not null default 0,
    language             varchar(500)    not null default '',
    frame                varchar(500)    not null default '',
    fixed_version        varchar(500)    not null default '',
    target               varchar(500)    not null default '',
    attack_path          varchar(30)     not null default '',
    flag                 bigint unsigned not null default 0,

    created_at           bigint unsigned not null default 0,
    updated_at           bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_unique (unique_id),
    unique index idx_vuln_name (`name`)
);

create table if not exists ivan_scanner_registries
(
    id               bigint auto_increment
        primary key,
    name             varchar(255)            null,
    reg_type         varchar(255)            null,
    url              varchar(255)            null,
    username         varchar(255)            null,
    password         blob                    null,
    description      varchar(255)            null,
    sync_interval    bigint                  null,
    last_sync_at     bigint       default 0  null,
    created_at       datetime(3)             null,
    updated_at       datetime(3)             null,
    deleted_at       bigint       default 0  null,
    access_key       varchar(100) default '' not null,
    access_secret    varchar(200) default '' not null,
    instance_id      varchar(200) default '' not null,
    region_id        varchar(200) default '' not null,
    cluster_key      varchar(200) default '' not null,
    scanner_instance varchar(200) default '' not null,
    status           varchar(200) default '' not null,
    health_msg       text                    null,
    heat_beat        bigint       default 0  not null,
    use_type         int          default 0  not null,
    unique index uniq_idx_registry_name (name, deleted_at)
);

create table if not exists ivan_scanner_sync_tasks
(
    id          bigint unsigned auto_increment
        primary key,
    registry_id bigint          default 0   not null,
    finish_at   bigint unsigned default '0' not null,
    sync_type   varchar(200)    default ''  not null,
    result      text                        null,
    created_at  bigint unsigned default '0' not null,
    start_at    bigint unsigned default '0' not null,
    unique index unq_idx_reg (registry_id, sync_type, finish_at)
);

create TABLE IF NOT EXISTS ivan_scanner_instance
(
    id               bigint unsigned auto_increment,
    cluster_key      varchar(200)    not null default '',
    cluster_name     varchar(200)    not null default '',
    scanner_instance varchar(200)    not null default '',
    scanner_pod_id   varchar(200)    not null default '',
    scanner_version  varchar(200)    not null default '',
    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,
    PRIMARY KEY (`id`),
    unique KEY idx_scanner_location (scanner_instance)
);

create table if not exists ivan_scan_sensitive_rule
(
    id            bigint unsigned auto_increment,
    `value`       varchar(500)    not null default '',
    `description` text            not null,
    rule_type     varchar(500)    not null default '',
    is_default    boolean         not null default false,
    `enable`      boolean         not null default false,
    updater       varchar(500)    not null default '',
    creator       varchar(500)    not null default '',

    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,
    primary key (id),
    unique index idx_sens_rule (`value`)
);

create table if not exists ivan_scan_image_config
(
    id            bigint unsigned auto_increment,
    `config_type` varchar(100)    not null default '',
    `config_data` longtext        not null,
    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,
    primary key (id),
    unique index idx_sens_rule (`config_type`)
);

create table if not exists ivan_image_vuln_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_sensitive_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_malware_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_pkg_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_license_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_webshell_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_root_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_env_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_detect_brief
(
    id               bigint unsigned auto_increment,
    flag             bigint unsigned not null default 0,
    policy_unique_id bigint unsigned not null default 0,
    image_unique_id  bigint unsigned not null default 0,
    policy_id        bigint unsigned not null default 0,
    policy           longtext        not null,
    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_policy (policy_id, image_unique_id),
    unique index unq_idx_image (image_unique_id, policy_id)
);

create table if not exists ivan_scan_image_env
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    image_unique_id bigint unsigned not null default 0 comment '镜像UniqueID',
    `key`           varchar(300)    not null default '' comment 'env KEY',
    `value`         text            not null comment 'env VALUE',
    layer_digest    varchar(100)    not null default '',

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,
    primary key (id),
    index idx_image (image_unique_id, `key`),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_scan_image_meta
(
    id               bigint unsigned auto_increment,
    unique_id        bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    image_id         varchar(300)    not null default '',
    image_from_type  varchar(10)     not null default '',
    `host`           varchar(200)    not null default '' comment '镜像host',
    repo             varchar(200)    not null default '' comment '镜像repo全名',
    tag              varchar(200)    not null default '' comment '镜像tag',
    namespace        varchar(200)    not null default '' comment '镜像的 namespace',
    image_name       varchar(500)    not null default '' comment '镜像全名',
    digest           varchar(100)    not null default '' comment '镜像digest',
    os               varchar(500)    not null default '' comment '镜像运行的OS',
    size             bigint unsigned not null default 0 comment '镜像大小，单位：byte',
    layer            longtext        not null comment '层级信息序列化后的数据',
    build_at         bigint unsigned not null default 0 comment '镜像build时间戳，单位：毫秒',
    `user`           varchar(300)    not null default '' comment '启动用户',
    flag             bigint unsigned not null default 0 comment '每一个二进制位标识一种类型的值',
    image_uuid       bigint unsigned not null default 0 comment '镜像uuid，用host+repo+tag生成，主在用于和资产关联',
    reg_id           bigint unsigned not null default 0,
    node_id          bigint unsigned not null default 0 comment '该镜像所在的节点uniqueId',
    project          varchar(200)    not null default '',
    heartbeat        bigint unsigned not null default 0,
    layer_str        longtext        not null,
    pull_count       bigint unsigned not null default 0,
    check_sum        bigint unsigned not null default 0,
    policy_unique_id varchar(500)    not null default '',
    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id),
    index `idx_image_flag` (`image_from_type`, `flag`),
    index `idx_heartbeat` (`heartbeat`),
    index `idx_image_project2` (`reg_id`, `project`, `image_from_type`),
    index `idx_image_project3` (`node_id`, `project`, `image_from_type`),
    index `idx_image_uuid` (`image_uuid`),
    index idx_image_digest (digest, image_from_type),
    index `idx_image_name2` (`image_name`, `image_from_type`)
);

create table if not exists ivan_scan_image_malware
(
    id            bigint unsigned auto_increment,
    unique_id     bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    `name`        varchar(500)    not null default '' comment '病毒名',
    filename      varchar(500)    not null default '' comment '病毒文件名',
    `hash`        varchar(500)    not null default '',
    malware_type  varchar(100)    not null default '',
    `description` longtext        not null,
    `version`     bigint unsigned not null default 0,
    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,
    primary key (id),
    index idx_node_malware (`name`),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_image_malware_issue
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0 comment '镜像UniqueID',
    layer_digest    varchar(100)    not null default '' comment '层级digest',
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index idx_image (image_unique_id, unique_target),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_scan_node_info
(
    id          bigint unsigned auto_increment,
    unique_id   bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    `hostname`  varchar(200)    not null default '' comment '节点host',
    ip          varchar(200)    not null default '' comment '节点IP',
    cluster_key varchar(200)    not null default '' comment '节点clusterKey',
    created_at  bigint unsigned not null default 0,
    updated_at  bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id),
    index unq_idx_cluster (cluster_key)
);

create table if not exists ivan_scan_image_pkg
(
    id          bigint unsigned auto_increment,
    unique_id   bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    `name`      varchar(500)    not null default '' comment 'pkg name',
    `version`   varchar(500)    not null default '',
    `os_family` varchar(50)     not null default '',
    `os_name`   varchar(50)     not null default '',
    pkg_type    varchar(300)    not null default '' comment 'debian,ubuntu...',
    src_name    varchar(300)    not null default '' comment 'trivy中SrcName',
    src_version varchar(300)    not null default '' comment 'trivy中SrcVersion',
    license     text            not null comment '开源协议',
    depends_on  longtext        not null comment '依赖文件',
    filepath    varchar(500)    not null default '' comment '文件路径',
    `class`     varchar(100)    not null default '',
    flag        bigint unsigned not null default 0,

    created_at  bigint unsigned not null default 0,
    updated_at  bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id),
    index idx_node_software (`name`)
);

create table if not exists ivan_image_pkg_issue
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0 comment '镜像UniqueID',
    layer_digest    varchar(100)    not null default '',

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index idx_image (image_unique_id, unique_target),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_image_detect_policy
(
    id               bigint unsigned auto_increment,
    unique_id        bigint unsigned not null default 0,
    policy_type      varchar(200)    not null default '',
    deploy_mod       varchar(200)    not null default '',
    enable           boolean         not null default false,
    `name`           varchar(300)    not null default '',
    `comment`        longtext        not null,
    is_default       boolean         not null default false,
    malware          longtext        not null comment '病毒策略',
    webshell         longtext        not null comment 'webshell策略',
    vuln             longtext        not null comment '漏洞策略',
    `sensitive`      longtext        not null comment '敏感文件策略',
    pkg              longtext        not null comment '软件包策略',
    license          longtext        not null comment '开源协议策略',
    pkg_license      longtext        not null,
    root_boot        longtext        not null,
    trust_image      longtext        not null,
    base_image       longtext        not null,
    exist_in_reg     longtext        not null,
    env              longtext        not null comment '环境变量策略',
    root_boot_enable boolean         not null default false,
    scope            longtext        not null comment '生效范围',
    creator          varchar(300)    not null default '',
    updater          varchar(300)    not null default '' comment '最近更新人',
    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,
    deleted_at       bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_name2 (`name`, policy_type, deleted_at)
);

create table if not exists ivan_scan_image_sensitive
(
    id             bigint unsigned auto_increment,
    unique_id      bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    `filename`     varchar(500)    not null default '' comment '敏感文件名',
    `md5`          varchar(100)    not null default '',
    description_zh longtext        not null comment '中文描述',
    description_en longtext        not null comment '英文描述',

    created_at     bigint unsigned not null default 0,
    updated_at     bigint unsigned not null default 0,
    primary key (id),
    index idx_node_sensitive (`filename`),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_image_sensitive_issue
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0 comment '镜像UniqueID',
    layer_digest    varchar(100)    not null default '',

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index idx_image (image_unique_id, unique_target),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_image_detect_task
(
    id               bigint unsigned auto_increment,
    `status`         bigint unsigned not null default 0,
    scan_sub_task_id bigint unsigned not null default 0,
    `status_str`     varchar(100)    not null default '',
    started_at       bigint unsigned not null default 0,
    finished_at      bigint unsigned not null default 0,
    priority         bigint unsigned not null default 0,
    updater          varchar(100)    not null default '',
    creator          varchar(100)    not null default '',
    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,

    primary key (id),
    index idx_task_priority1 (priority, `status`, scan_sub_task_id),
    index idx_task_status2 (`status`, `priority`, scan_sub_task_id)
);

create table if not exists ivan_image_detect_subtask
(
    id              bigint unsigned auto_increment,
    task_id         bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0 comment '镜像UniqueID',
    policy_id       bigint unsigned not null default 0,
    `status_str`    varchar(100)    not null default '',
    `status`        bigint unsigned not null default 0,
    started_at      bigint unsigned not null default 0,
    finished_at     bigint unsigned not null default 0,
    msg             longtext        not null,
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    unique index idx_image_task2 (task_id, image_unique_id, policy_id),
    index idx_task_image2 (policy_id, image_unique_id),
    index idx_task_image3 (image_unique_id, status)
);

create table if not exists ivan_image_scan_task
(
    id               bigint unsigned auto_increment,
    scan_type        varchar(100)    not null default '',
    image_from_type  varchar(100)    not null default '',
    `status`         bigint unsigned not null default 0,
    `status_str`     varchar(100)    not null default '',
    priority         bigint unsigned not null default 0,
    image_list_param longtext        not null,
    updater          varchar(100)    not null default '',
    creator          varchar(100)    not null default '',
    started_at       bigint unsigned not null default 0,
    finished_at      bigint unsigned not null default 0,
    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,

    primary key (id),
    index idx_task_status (`status`)
);

create table ivan_image_scan_subtask
(
    id              bigint unsigned auto_increment,
    task_id         bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0 comment '镜像UniqueID',
    node_unique_id  bigint unsigned not null default 0,
    image_name      varchar(300)    not null default '',
    node_host_name  varchar(200)    not null default '',
    `status`        bigint unsigned not null default 0,
    `status_str`    varchar(100)    not null default '',
    started_at      bigint unsigned not null default 0,
    finished_at     bigint unsigned not null default 0,
    heart_beat      bigint unsigned not null default 0,
    msg             longtext        not null,
    reason          varchar(200)    not null default '',
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index idx_image_task (task_id, status, node_unique_id),
    index idx_task_image (node_unique_id, status, task_id),
    index idx_image_unique_id (image_unique_id)
);

create table if not exists ivan_scan_image_vuln
(
    id                   bigint unsigned auto_increment,
    unique_id            bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    pkg_unique_id        bigint unsigned not null default 0,
    `name`               varchar(100)    not null default '',
    pkg_name             varchar(100)    not null default '',
    src_name             varchar(300)    not null default '',
    src_version          varchar(300)    not null default '',
    pkg_version          varchar(100)    not null default '',
    cnnvd_name           varchar(300)    not null default '',
    cnnvd_fix_suggestion text            not null,
    description_en       text            not null,
    description_zh       text            not null,
    pkg_type             varchar(50)     not null default '',
    `references`         longtext        not null,
    `class`              varchar(200)    not null default '',
    `cvss`               longtext        not null,
    `ced_ids`            text            not null,
    `title`              text            not null,
    `cnvd_title`         text            not null,
    publish_at           bigint unsigned not null default 0,
    modify_at            bigint unsigned not null default 0,
    severity             bigint unsigned not null default 0,
    check_sum            bigint unsigned not null default 0,
    language             varchar(500)    not null default '',
    frame                varchar(500)    not null default '',
    fixed_version        varchar(500)    not null default '',
    target               varchar(500)    not null default '',
    attack_path          varchar(30)     not null default '',
    flag                 bigint unsigned not null default 0,

    created_at           bigint unsigned not null default 0,
    updated_at           bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id),
    index idx_vuln_name (`name`, `pkg_name`, `pkg_version`)
);

create table if not exists ivan_image_vuln_issue
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    layer_digest    varchar(100)    not null default '' comment '层级digest',
    flag            bigint unsigned not null default 0 comment '每一个二进制位标识一种类型的值',
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index idx_image (image_unique_id, unique_target),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_scan_image_webshell
(
    id            bigint unsigned auto_increment,
    unique_id     bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    filename      varchar(500)    not null default '' comment '文件名',
    `md5`         varchar(64)     not null default '' comment '文件md5值',
    `file_mod`    varchar(200)    not null default 0 comment '文件权限',
    `code`        longtext        not null comment '代码片段',
    size          bigint unsigned not null default 0,
    risk_level    varchar(200)    not null default '',
    `description` varchar(500)    not null default '',
    `version`     bigint unsigned not null default 0,
    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id),
    index idx_hash (`md5`)
);

create table if not exists ivan_image_webshell_issue
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0 comment '镜像UniqueID',
    layer_digest    varchar(100)    not null default '' comment '层级digest',
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index idx_image (image_unique_id, unique_target),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_scan_deploy_record
(
    id               bigint unsigned auto_increment,
    image_uuid       bigint unsigned not null default 0,
    image_unique_id  bigint unsigned not null default 0,
    image_name       varchar(500)    not null default '',
    host             varchar(500)    not null default '',
    repo             varchar(500)    not null default '',
    tag              varchar(500)    not null default '',
    image            longtext        not null,
    digest           varchar(100)    not null default '',
    action           varchar(100)    not null default '',
    vuln             longtext        not null,
    malware          longtext        not null,
    webshell         longtext        not null,
    `sensitive`      longtext        not null,
    pkg              longtext        not null,
    license          longtext        not null,
    env              longtext        not null,
    root_boot        longtext        not null,
    base_image       longtext        not null,
    trusted_image    longtext        not null,
    risk_policy      longtext        not null,
    total_policy     longtext        not null,
    policy_unique_id varchar(500)    not null,
    hour             bigint unsigned not null default 0,
    day              bigint unsigned not null default 0,
    flag             bigint unsigned not null default 0,
    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,

    primary key (id),
    index idx_image_uuid (image_uuid, flag),
    index idx_image_hour (hour, flag),
    index idx_image_day (day, flag),
    index idx_image_flag (flag, image_uuid),
    index idx_created_flag (created_at, flag)
);

create table if not exists ivan_scan_deploy_white_image
(
    id            bigint unsigned auto_increment,
    image_name    varchar(500)    not null default '',
    creator       varchar(300)    not null default '',
    updater       varchar(300)    not null default '',
    expiration_at bigint unsigned not null default 0,


    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index idx_image_name (image_name)
);

create table if not exists ivan_scan_data_migrate
(
    id           bigint unsigned auto_increment,
    soft_version varchar(100)    not null default '',
    model        varchar(50)     not null default '',
    last         longtext        not null,
    started_at   bigint unsigned not null default 0,
    finished_at  bigint unsigned not null default 0,


    created_at   bigint unsigned not null default 0,
    updated_at   bigint unsigned not null default 0,

    primary key (id),
    unique index idx_ver (soft_version, model)
);

create table if not exists ivan_scan_image_license
(
    id         bigint unsigned auto_increment,
    unique_id  bigint unsigned not null default 0,
    `name`     varchar(500)    not null default '',
    `filename` varchar(500)    not null default '',
    `md5`      varchar(500)    not null default '',
    `content`  longtext        not null,
    created_at bigint unsigned not null default 0,
    updated_at bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_image_license_issue
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0 comment '镜像UniqueID',
    layer_digest    varchar(100)    not null default '' comment '层级digest',
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index idx_image (image_unique_id, unique_target),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_scan_vuln_pkg
(
    id            bigint unsigned auto_increment,
    unique_id     bigint unsigned not null default 0,
    pkg_unique_id bigint unsigned not null default 0,
    `vuln_name`   varchar(100)    not null default '',
    flag          bigint unsigned not null default 0,

    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id),
    index idx_pkg (pkg_unique_id, vuln_name),
    index idx_vuln (vuln_name, pkg_unique_id)
);

create table if not exists ivan_scan_image_cache
(
    id         bigint unsigned auto_increment,
    data_type  varchar(100)    not null default '',
    data       longtext        not null,
    created_at bigint unsigned not null default 0,
    updated_at bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_cache_type (data_type)
);

CREATE TABLE if not exists `ivan_scanner_image_list`
(
    `id`                bigint          NOT NULL AUTO_INCREMENT,
    `created_at`        datetime(3)              DEFAULT NULL,
    `updated_at`        datetime(3)              DEFAULT NULL,
    `full_repo_name`    varchar(255)             DEFAULT NULL,
    `tags`              varchar(255)             DEFAULT NULL,
    `digest`            varchar(255)             DEFAULT NULL,
    `os`                varchar(255)             DEFAULT NULL,
    `size`              bigint                   DEFAULT NULL,
    `library`           varchar(255)             DEFAULT NULL,
    `image_uuid`        int unsigned             DEFAULT NULL,
    `complete_time`     varchar(255)             DEFAULT NULL,
    `on_line_count`     bigint                   DEFAULT '0',
    `status`            bigint                   DEFAULT '0',
    `registry_id`       bigint                   DEFAULT NULL,
    `first_push_time`   datetime(3)              DEFAULT NULL,
    `last_push_time`    datetime(3)     NOT NULL,
    `last_pull_time`    datetime(3)              DEFAULT NULL,
    `manifest_v1_json`  blob,
    `manifest_v2_json`  blob,
    `config_json`       mediumblob,
    `from_type`         bigint                   DEFAULT NULL,
    `layers`            text,
    `node_ip`           varchar(255)             DEFAULT NULL,
    `node_hostname`     varchar(255)             DEFAULT NULL,
    `image_type`        bigint                   DEFAULT '0',
    `project`           varchar(255)             DEFAULT NULL,
    `repo_name`         varchar(255)             DEFAULT NULL,
    `privileged_boot`   bigint                   DEFAULT NULL,
    `is_reinforce`      bigint                   DEFAULT NULL,
    `flag`              bigint unsigned NOT NULL DEFAULT '0' COMMENT '保存的flag信息,用于快速统计',
    `check_sum`         bigint unsigned NOT NULL DEFAULT '0' COMMENT '这一行数据的check值，用于判断这一行数据是否有变动',
    `unique_image`      bigint unsigned          DEFAULT NULL,
    `last_full_sync_at` bigint unsigned NOT NULL DEFAULT '0',
    `pull_count`        bigint          NOT NULL DEFAULT '0',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uniq_idx_image_list` (`full_repo_name`, `tags`, `registry_id`, `from_type`),
    UNIQUE KEY `uniq_idx_unique_image` (`unique_image`),
    KEY `idx_image_digest` (`digest`),
    KEY `idx_image_layers` (`layers`(200)),
    KEY `idx_uuid` (`image_uuid`),
    KEY `idx_flag` (`flag`, `from_type`, `image_uuid`),
    KEY `idx_project` (`project`, `registry_id`, `flag`),
    KEY `idx_last_full_sync_at` (`registry_id`, `last_full_sync_at`),
    KEY `index_library` (`library`),
    KEY `idx_updated_at` (`updated_at`)
) ENGINE = InnoDB;

create table if not exists ivan_scan_malware_version
(
    id             bigint unsigned auto_increment,
    unique_id      bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',

    engine_version varchar(200)    not null default '' comment '引擎版本号',
    engine_comment longtext        not null comment '引擎备注',
    db_version     varchar(200)    not null default '' comment 'db版本号',
    db_comment     longtext        not null comment 'db备注',
    db_hash        varchar(100)    not null default '' comment 'db的hash值',
    engine_hash    varchar(100)    not null default '' comment 'engin的hash值',
    updater        varchar(400)    not null default '' comment '最近一次更新人',
    update_at      bigint unsigned not null default 0 comment '最近一次更新时间戳，单位：毫秒',
    `enable`       boolean         not null default false comment '是否启用',

    created_at     bigint unsigned not null default 0,
    updated_at     bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_scan_vuln_version
(
    id             bigint unsigned auto_increment,
    unique_id      bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',

    engine_version varchar(200)    not null default '' comment '引擎版本号',
    engine_comment longtext        not null comment '引擎备注',
    db_version     varchar(200)    not null default '' comment 'db版本号',
    db_comment     longtext        not null comment 'db备注',
    db_hash        varchar(100)    not null default '' comment 'db的hash值',
    updater        varchar(400)    not null default '' comment '最近一次更新人',
    update_at      bigint unsigned not null default 0 comment '最近一次更新时间戳，单位：毫秒',
    `enable`       boolean         not null default false comment '是否启用',

    created_at     bigint unsigned not null default 0,
    updated_at     bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_scan_webshell_version
(
    id             bigint unsigned auto_increment,
    unique_id      bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',

    engine_version varchar(200)    not null default '' comment '引擎版本号',
    engine_comment longtext        not null comment '引擎备注',
    db_version     varchar(200)    not null default '' comment 'db版本号',
    db_comment     longtext        not null comment 'db备注',
    db_hash        varchar(100)    not null default '' comment 'db的hash值',
    engine_hash    varchar(100)    not null default '' comment 'engin的hash值',
    updater        varchar(400)    not null default '' comment '最近一次更新人',
    update_at      bigint unsigned not null default 0 comment '最近一次更新时间戳，单位：毫秒',
    `enable`       boolean         not null default false comment '是否启用',

    created_at     bigint unsigned not null default 0,
    updated_at     bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_scan_sensitive_version
(
    id         bigint unsigned auto_increment,
    unique_id  bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',

    rules      longtext        not null comment '规则',
    rule_hash  varchar(100)    not null default '' comment '规则hash',
    updater    varchar(400)    not null default '' comment '最近一次更新人',
    update_at  bigint unsigned not null default 0 comment '最近一次更新时间戳，单位：毫秒',
    `enable`   boolean         not null default false comment '是否启用',

    created_at bigint unsigned not null default 0,
    updated_at bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id)
);

create table if not exists ivan_scan_db_config
(
    id         bigint unsigned auto_increment,
    unique_id  bigint unsigned not null default 0,
    db_version varchar(100)    not null default '',
    db_type    varchar(100)    not null default '',
    db_md5     varchar(100)    not null default '',
    meta       longtext        not null,
    updater    varchar(400)    not null default '' comment '最近一次更新人',
    created_at bigint unsigned not null default 0,
    updated_at bigint unsigned not null default 0,
    primary key (id),
    index unq_idx_unique (unique_id)
);

create table if not exists ivan_scan_data_layer
(
    id         bigint unsigned auto_increment,
    unique_id  bigint unsigned not null default 0,
    layer      varchar(100)    not null default '',
    issue      varchar(100)    not null default '',
    db_version varchar(100)    not null default '',
    data       longtext        not null,
    created_at bigint unsigned not null default 0,
    updated_at bigint unsigned not null default 0,
    primary key (id),
    unique index unq_idx_unique (unique_id),
    index idx_ly (layer)
);

create table if not exists ivan_scan_file_layer
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0,
    layer_unique_id bigint unsigned not null default 0,
    file_md5        varchar(100)    not null default '',
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,
    primary key (id),
    unique index unq_idx_unique (unique_id),
    index idx_file_layer (file_md5, layer_unique_id)
);
