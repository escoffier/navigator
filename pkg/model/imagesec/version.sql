drop table if exists ivan_scan_malware_version;
drop table if exists ivan_scan_vuln_version;
drop table if exists ivan_scan_webshell_version;
drop table if exists ivan_scan_sensitive_version;


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