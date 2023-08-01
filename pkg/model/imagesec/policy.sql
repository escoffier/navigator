drop table if exists ivan_image_detect_policy;
drop table if exists ivan_detect_policy_snapshot;

create table if not exists ivan_image_detect_policy
(
    id          bigint unsigned auto_increment,
    unique_id   bigint unsigned not null default 0,
    policy_type varchar(200)    not null default '',
    deploy_mod  varchar(200)    not null default '',
    enable      bool            not null default false,
    `name`      varchar(300)    not null default '',
    `comment`   longtext        not null,
    is_default  boolean         not null default false,
    malware     longtext        not null comment '病毒策略',
    webshell    longtext        not null comment 'webshell策略',
    vuln        longtext        not null comment '漏洞策略',
    `sensitive` longtext        not null comment '敏感文件策略',
    pkg         longtext        not null comment '软件包策略',
    license     longtext        not null comment '许可文件',
    pkg_license longtext        not null comment '不允许的软件许可',
    env         longtext        not null comment '环境变量策略',
    root_boot   longtext        not null,
    trust_image longtext        not null,
    base_image  longtext        not null,
    scope       longtext        not null comment '生效范围',

    creator     varchar(300)    not null default '',
    updater     varchar(300)    not null default '' comment '最近更新人',
    created_at  bigint unsigned not null default 0,
    updated_at  bigint unsigned not null default 0,
    deleted_at  bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_name (`name`, policy_type, deleted_at)
);



create table if not exists ivan_detect_policy_snapshot
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0,
    security_policy longtext        not null,
    created_at      bigint unsigned not null default 0,

    primary key (id),
    unique index unq_unique_id (unique_id)
);