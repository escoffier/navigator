drop table if exists ivan_scan_image_sensitive;
drop table if exists ivan_image_sensitive_issue;


create table if not exists ivan_scan_image_sensitive
(
    id             bigint unsigned auto_increment,
    unique_id      bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    `name`         varchar(500)    not null default '' comment '敏感文件名',
    description_zh longtext        not null comment '中文描述',
    description_en longtext        not null comment '英文描述',

    created_at     bigint unsigned not null default 0,
    updated_at     bigint unsigned not null default 0,
    primary key (id),
    index idx_node_sensitive (`name`),
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

