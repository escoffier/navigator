alter table ivan_scan_image_meta
    drop column namespace;

alter table ivan_image_scan_subtask
    drop column scan_uuid;
drop table ivan_scan_db_config;
drop table ivan_scan_data_layer;
drop table ivan_scan_file_layer;

alter table ivan.ivan_image_scan_subtask
    add column cluster_key varchar(100) not null default '' after task_id;



alter table ivan_scanner_image_list
    drop index idx_status;

alter table ivan_scanner_scan_task
    drop index idx_status;

alter table ivan_scanner_scan_subtask
    drop index idx_status;