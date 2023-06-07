drop table if exists ivan_scan_image_pkg;
drop table if exists ivan_image_pkg_issue;


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
