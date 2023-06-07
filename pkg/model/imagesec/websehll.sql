drop table if exists ivan_scan_image_webshell;
drop table if exists ivan_image_webshell_issue;


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