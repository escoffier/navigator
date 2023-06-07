drop table if exists ivan_scan_image_meta;

create table if not exists ivan_scan_image_meta
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    image_id        varchar(100)    not null default '',
    image_from_type varchar(10)     not null default '',
    `host`          varchar(200)    not null default '' comment '镜像host',
    repo            varchar(200)    not null default '' comment '镜像repo全名',
    tag             varchar(200)    not null default '' comment '镜像tag',
    image_name      varchar(500)    not null default '' comment '镜像全名',
    digest          varchar(100)    not null default '' comment '镜像digest',
    os              varchar(500)    not null default '' comment '镜像运行的OS',
    size            bigint unsigned not null default 0 comment '镜像大小，单位：byte',
    layer           longtext        not null comment '层级信息序列化后的数据',
    build_at        bigint unsigned not null default 0 comment '镜像build时间戳，单位：毫秒',
    `user`          varchar(300)    not null default '' comment '启动用户',
    flag            bigint unsigned not null default 0 comment '每一个二进制位标识一种类型的值',
    image_uuid      bigint unsigned not null default 0 comment '镜像uuid，用host+repo+tag生成，主在用于和资产关联',
    reg_id          bigint unsigned not null default 0,
    node_id         bigint unsigned not null default 0 comment '该镜像所在的节点uniqueId',
    project         varchar(200)    not null default '',
    heartbeat       bigint unsigned not null default 0,
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id),
    index idx_image_flag (image_from_type, flag),
    index idx_image_project (image_from_type, project),
    index idx_image_name (image_from_type, image_name)
);

