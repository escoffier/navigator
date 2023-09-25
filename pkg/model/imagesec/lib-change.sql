truncate table ivan_scanner_sync_tasks;
truncate table ivan_image_detect_task;
truncate table ivan_image_detect_subtask;


alter table ivan_image_detect_task
    drop column image_from_type;

alter table ivan_scanner_sync_tasks
    add unique index unq_idx_reg (registry_id, finish_at);

alter table ivan_scanner_sync_tasks
    add column start_at bigint unsigned not null default 0 after sync_type;



alter table ivan_scan_image_sensitive
    add column `md5` varchar(100) not null default '' after name;

alter table ivan_image_detect_policy
    add column unique_id bigint unsigned not null default 0 after id;

alter table ivan_image_detect_brief
    add column policy_unique_id bigint unsigned not null default 0 after flag;

alter table ivan_image_detect_subtask
    add column policy_id bigint unsigned not null default 0 after image_unique_id;

alter table ivan_image_detect_subtask
    add unique index idx_image_task2 (task_id, image_unique_id, policy_id);
alter table ivan_image_detect_subtask
    add index idx_task_image2 (policy_id, image_unique_id);
alter table ivan_image_detect_subtask
    add index idx_task_image3 (image_unique_id, status);


alter table ivan_image_detect_subtask
    drop index idx_image_task;


alter table ivan_image_detect_subtask
    drop index idx_task_image;


alter table ivan_image_detect_subtask
    drop column policy_ids;



alter table ivan_image_detect_policy
    add column policy_type varchar(200) not null default '' after unique_id;
alter table ivan_image_detect_policy
    add column deploy_mod varchar(200) not null default '' after policy_type;

alter table ivan_scan_image_meta
    modify column image_id varchar(300) not null default '';


alter table ivan_image_detect_policy
    add column enable boolean not null default false after deploy_mod;

alter table ivan_image_detect_policy
    add column pkg_license longtext not null after license;

alter table ivan_image_detect_policy
    add column root_boot longtext not null after pkg_license;

alter table ivan_image_detect_policy
    add column trust_image longtext not null after root_boot;

alter table ivan_image_detect_policy
    add column base_image longtext not null after trust_image;

alter table ivan_image_detect_policy
    add column exist_in_reg longtext not null after base_image;



alter table ivan_image_detect_policy
    drop column root_boot_enable;

alter table ivan_image_detect_policy
    add unique index unq_idx_name2 (`name`, policy_type, deleted_at);

alter table ivan_image_detect_policy
    drop index unq_idx_name;


alter table ivan_scan_image_meta
    add column layer_str longtext not null after layer;

alter table ivan_scan_image_meta
    add column pull_count bigint unsigned not null default 0 after heartbeat;


alter table ivan_scan_image_meta
    add column policy_unique_id varchar(500) not null default '' after pull_count;

delete
from ivan_scanner_registries
where use_type != 1;

alter table ivan_scanner_registries
    drop column use_type;


ALTER TABLE ivan_image_scan_subtask RENAME COLUMN node_host_name TO hostname;
ALTER TABLE ivan_image_scan_subtask RENAME COLUMN node_cluster_key TO cluster_key;
ALTER TABLE ivan_scan_image_sensitive RENAME COLUMN name TO filename;

alter table ivan_image_scan_subtask
    add column scan_ins_ver varchar(100) not null default '' after hostname;

alter table ivan_scan_image_vuln
    add column attack_path varchar(30) not null default '' after target;


alter table ivan_image_scan_subtask
    add index idx_image_unique_id (image_unique_id);



alter table ivan_scanner_image_list
    add index idx_updated_at (updated_at);

update ivan_image_detect_policy
set policy_type = 'nodeImage'
where id > 0;

alter table ivan_export_task
    add index idx_execute_type (execute_type);


update ivan_export_task
set execute_type = 'ExportImageSearch'
where execute_type in ('ExportImageSearch', 'ExportNodeImageSearch', 'ExportImage');



create table if not exists ivan_detect_policy_snapshot
(
    id              bigint unsigned auto_increment,
    policy_id       bigint unsigned not null default 0,
    unique_id       bigint unsigned not null default 0,
    security_policy longtext        not null,
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    unique index unq_unique_id (unique_id)
);


create table if not exists ivan_image_exist_reg_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);



create table if not exists ivan_image_base_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);


create table if not exists ivan_image_trusted_detect
(
    id              bigint unsigned auto_increment,
    flag            bigint unsigned not null default 0,
    unique_target   bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0,
    policy_id       bigint unsigned not null default 0,

    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
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
    attack_path          varchar(30)     not null default '',
    flag                 bigint unsigned not null default 0,

    created_at           bigint unsigned not null default 0,
    updated_at           bigint unsigned not null default 0,

    primary key (id),
    index unq_idx_unique (unique_id),
    unique index idx_vuln_name (`name`)
);



alter table ivan_image_vuln_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_sensitive_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_malware_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_pkg_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_license_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_webshell_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_root_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_env_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_base_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_trusted_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_exist_reg_detect
    add index unq_idx_policy (policy_id, image_unique_id);
alter table ivan_image_detect_brief
    add index unq_idx_policy (policy_id, image_unique_id);

