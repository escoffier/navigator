# 需要配置的数据
truncate table ivan_scan_sensitive_rule;
truncate table ivan_scan_image_config;
truncate table ivan_image_detect_policy;
truncate table ivan_scan_deploy_white_image;
truncate table ivan_scanner_instance;
truncate table ivan_scan_db_config;
truncate table ivan_scan_node_info;
truncate table ivan_scan_data_layer;
truncate table ivan_scan_file_layer;

# 扫描等生成的数据
truncate table ivan_detect_policy_snapshot;
truncate table ivan_image_detect_task;
truncate table ivan_image_detect_subtask;
truncate table ivan_image_vuln_detect;
truncate table ivan_image_sensitive_detect;
truncate table ivan_image_malware_detect;
truncate table ivan_image_pkg_detect;
truncate table ivan_image_license_detect;
truncate table ivan_image_webshell_detect;
truncate table ivan_image_root_detect;
truncate table ivan_image_base_detect;
truncate table ivan_image_trusted_detect;
truncate table ivan_image_exist_reg_detect;
truncate table ivan_image_detect_brief;
truncate table ivan_image_pkg_issue;
truncate table ivan_image_license_issue;
truncate table ivan_image_vuln_issue;
truncate table ivan_image_webshell_issue;
truncate table ivan_image_sensitive_issue;
truncate table ivan_image_malware_issue;
truncate table ivan_scan_image_pkg;
truncate table ivan_scan_image_vuln;
truncate table ivan_scan_image_malware;
truncate table ivan_scan_image_license;
truncate table ivan_scan_image_env;
truncate table ivan_scan_image_sensitive;
truncate table ivan_scan_online_vuln;
truncate table ivan_scanner_sync_tasks;
truncate table ivan_scan_image_cache;
truncate table ivan_scan_image_meta;
truncate table ivan_image_scan_task;
truncate table ivan_image_scan_subtask;
truncate table ivan_scan_malware_version;
truncate table ivan_scan_vuln_version;
truncate table ivan_scan_webshell_version;
truncate table ivan_scan_sensitive_version;
truncate table ivan_scan_deploy_record;

truncate table ivan_scanner_scan_task;
truncate table ivan_scanner_scan_subtask;
truncate table ivan_scanner_image_list;
truncate table ivan_scanner_scan_images;


