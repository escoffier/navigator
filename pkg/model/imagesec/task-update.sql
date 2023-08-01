update ivan_scanner_scan_task
set operator = 'cicd'
where operator = 'CICD触发扫描';
update ivan_scanner_scan_task
set operator = 'syncImage'
where operator = '周期触发扫描';
update ivan_scanner_scan_task
set operator = 'cycle'
where operator = '镜像同步触发扫描';
