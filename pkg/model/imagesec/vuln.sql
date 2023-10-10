drop table if exists ivan_scan_image_vuln;
drop table if exists ivan_image_vuln_issue;
drop table if exists ivan_scan_online_vuln;
drop table if exists ivan_scan_vuln_pkg;

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
    flag                 bigint unsigned not null default 0,

    created_at           bigint unsigned not null default 0,
    updated_at           bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_unique (unique_id),
    unique index idx_vuln_name (`name`)
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
)


