alter table ivan_scan_deploy_record
    drop column last_scan_at;
ALTER TABLE ivan_scan_deploy_record
    drop COLUMN policy;

alter table ivan_scan_deploy_record
    add column risk_policy longtext not null after trusted_image;
alter table ivan_scan_deploy_record
    add column total_policy longtext not null after risk_policy;

drop table ivan_scan_image_cache;

create table if not exists ivan_scan_image_cache
(
    id         bigint unsigned auto_increment,
    data_type  varchar(100)    not null default '',
    data       longtext        not null,
    created_at bigint unsigned not null default 0,
    updated_at bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_cache_type (data_type)
);

alter table ivan_image_scan_subtask
    add index idx_image_task2 (task_id, status, node_unique_id);

alter table ivan_image_scan_subtask
    add index idx_task_image2 (node_unique_id, status, task_id);

alter table ivan_image_scan_subtask drop index idx_image_task;
alter table ivan_image_scan_subtask drop index idx_task_image;