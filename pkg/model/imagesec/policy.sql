drop table if exists ivan_image_detect_policy;

create table if not exists ivan_image_detect_policy
(
    id               bigint unsigned auto_increment,
    `name`           varchar(300)    not null default '',
    `comment`        longtext        not null,
    is_default       boolean         not null default false,
    malware          longtext        not null comment '病毒策略',
    webshell         longtext        not null comment 'webshell策略',
    vuln             longtext        not null comment '漏洞策略',
    `sensitive`      longtext        not null comment '敏感文件策略',
    pkg              longtext        not null comment '软件包策略',
    license          longtext        not null comment '开源协议策略',
    env              longtext        not null comment '环境变量策略',
    root_boot_enable boolean         not null default false,
    scope            longtext        not null comment '生效范围',
    creator          varchar(300)    not null default '',
    updater          varchar(300)    not null default '' comment '最近更新人',
    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,
    deleted_at       bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_name (`name`, deleted_at)
);

