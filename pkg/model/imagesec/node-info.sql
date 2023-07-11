drop table if exists ivan_scan_node_info;

create table if not exists ivan_scan_node_info
(
    id          bigint unsigned auto_increment,
    unique_id   bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',
    `hostname`  varchar(200)    not null default '' comment '节点host',
    ip          varchar(200)    not null default '' comment '节点IP',
    cluster_key varchar(200)    not null default '' comment '节点clusterKey',
    clamav_db   bigint unsigned not null default 0,
    avira_db   bigint unsigned not null default 0,
    webshell_db   bigint unsigned not null default 0,


    created_at  bigint unsigned not null default 0,
    updated_at  bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_unique (unique_id),
    index unq_idx_cluster (cluster_key)
);