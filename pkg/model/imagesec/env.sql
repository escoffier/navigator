drop table if exists ivan_scan_image_env;

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
