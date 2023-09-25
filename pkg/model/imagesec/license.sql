drop table if exists ivan_scan_image_license;
drop table if exists ivan_image_license_issue;


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

