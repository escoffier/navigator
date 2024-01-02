alter table ivan_scan_image_meta
    add column namespace varchar(200) not null default '' comment '镜像的 namespace' after tag;

alter table ivan_image_scan_subtask
    add column scan_uuid varchar(200) not null default '' after scan_ins_ver;

alter table ivan_image_scan_subtask
    drop column cluster_key;
alter table ivan_ci_policies
    modify column `sensitive_file_policy` longtext not null;

create table if not exists ivan_scan_db_config
(
    id         bigint unsigned auto_increment,
    unique_id  bigint unsigned not null default 0 comment '生成的ID，关联数据时不用事务',

    db_version varchar(100)    not null default '',
    db_type    varchar(100)    not null default '',
    db_md5     varchar(100)    not null default '',
    meta       longtext        not null,
    updater    varchar(400)    not null default '' comment '最近一次更新人',
    created_at bigint unsigned not null default 0,
    updated_at bigint unsigned not null default 0,
    primary key (id),
    index unq_idx_unique (unique_id)
);



create table if not exists ivan_scan_data_layer
(
    id         bigint unsigned auto_increment,
    unique_id  bigint unsigned not null default 0,
    layer      varchar(100)    not null default '',
    issue      varchar(100)    not null default '',
    db_version varchar(100)    not null default '',
    data       longtext        not null,
    created_at bigint unsigned not null default 0,
    updated_at bigint unsigned not null default 0,
    primary key (id),
    unique index unq_idx_unique (unique_id),
    index idx_ly (layer)
);


create table if not exists ivan_scan_file_layer
(
    id              bigint unsigned auto_increment,
    unique_id       bigint unsigned not null default 0,
    layer_unique_id bigint unsigned not null default 0,
    file_md5        varchar(100)    not null default '',
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,
    primary key (id),
    unique index unq_idx_unique (unique_id),
    index idx_file_layer (file_md5, layer_unique_id)
);


update ivan_scanner_scan_config
set vuln_flush_trig_enable = false
where id > 0;
update ivan_scanner_scan_config
set malicious_flush_trig_enable = false
where id > 0;
update ivan_scanner_scan_config
set library_image_add_trig_enable = false
where id > 0;
update ivan.ivan_scanner_scan_config
set node_image_add_trig_enable = false
where id > 0;
update ivan.ivan_scanner_scan_config
set library_image_config = ''
where id > 0;
update ivan.ivan_scanner_scan_config
set node_image_config =''
where id > 0;

alter table ivan_scanner_image_list
    add index idx_status (status);

alter table ivan_scanner_scan_task
    add index idx_status (status);

alter table ivan_scanner_scan_subtask
    add index idx_status (status);


/*

中移兼容
truncate table ivan_scanner_image_list;
truncate table ivan_scanner_scan_images;
truncate table ivan_scanner_scan_task;
truncate table ivan_scanner_scan_subtask;
truncate table ivan_scanner_vuln_images;
truncate table ivan_sensitive_issue_image;
truncate table ivan_software_issue_image;

*/