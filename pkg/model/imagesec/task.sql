drop table if exists ivan_image_detect_task;
drop table if exists ivan_image_detect_subtask;
drop table if exists ivan_image_scan_task;
drop table if exists ivan_image_scan_subtask;


create table if not exists ivan_image_detect_task
(
    id               bigint unsigned auto_increment,
    image_from_type  varchar(100)    not null default '',
    `status`         bigint unsigned not null default 0,
    scan_sub_task_id bigint unsigned not null default 0,
    `status_str`     varchar(100)    not null default '',
    started_at       bigint unsigned not null default 0,
    finished_at      bigint unsigned not null default 0,
    priority         bigint unsigned not null default 0,
    updater          varchar(100)    not null default '',
    creator          varchar(100)    not null default '',
    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,

    primary key (id),
    index idx_task_priority (priority, `status`, scan_sub_task_id),
    index idx_task_status (`status`, priority, scan_sub_task_id)
);

create table if not exists ivan_image_detect_subtask
(
    id              bigint unsigned auto_increment,
    task_id         bigint unsigned not null default 0,
    image_unique_id bigint unsigned not null default 0 comment '镜像UniqueID',
    policy_id       bigint unsigned not null default 0,
    `status_str`    varchar(100)    not null default '',
    `status`        bigint unsigned not null default 0,
    started_at      bigint unsigned not null default 0,
    finished_at     bigint unsigned not null default 0,
    msg             longtext        not null,
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index idx_image_task (task_id, image_unique_id),
    index idx_task_image (image_unique_id, task_id)
);


create table if not exists ivan_image_scan_task
(
    id               bigint unsigned auto_increment,
    scan_type        varchar(100)    not null default '',
    image_from_type  varchar(100)    not null default '',
    `status`         bigint unsigned not null default 0,
    `status_str`     varchar(100)    not null default '',
    priority         bigint unsigned not null default 0,
    image_list_param longtext        not null,
    updater          varchar(100)    not null default '',
    creator          varchar(100)    not null default '',
    started_at       bigint unsigned not null default 0,
    finished_at      bigint unsigned not null default 0,
    scan_ins_ver     varchar(100)    not null default '',
    image_id         bigint unsigned not null default 0,

    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,

    primary key (id),
    index idx_task_status (`status`)
);



create table if not exists ivan_image_scan_subtask
(
    id              bigint unsigned auto_increment,
    task_id         bigint unsigned not null default 0,
    cluster_key     varchar(100)    not null default '',
    image_unique_id bigint unsigned not null default 0 comment '镜像UniqueID',
    node_unique_id  bigint unsigned not null default 0,
    image_name      varchar(300)    not null default '',
    hostname        varchar(200)    not null default '',
    `status`        bigint unsigned not null default 0,
    `status_str`    varchar(100)    not null default '',
    started_at      bigint unsigned not null default 0,
    finished_at     bigint unsigned not null default 0,
    heart_beat      bigint unsigned not null default 0,
    msg             longtext        not null,
    reason          varchar(200)    not null default '',
    created_at      bigint unsigned not null default 0,
    updated_at      bigint unsigned not null default 0,

    primary key (id),
    index idx_image_task (task_id, node_unique_id),
    index idx_task_image (node_unique_id, task_id)
);
