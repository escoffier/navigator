truncate table ivan_scanner_image_list;
truncate table ivan_scanner_scan_images;
truncate table ivan_scanner_scan_task;
truncate table ivan_scanner_scan_subtask;
truncate table ivan_scanner_vuln_images;
truncate table ivan_sensitive_issue_image;
truncate table ivan_software_issue_image;

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