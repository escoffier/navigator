use ivan;

drop Table if exists portal_user;

drop Table if exists portal_project;

DROP TABLE IF EXISTS codesec_vuln;

DROP TABLE IF EXISTS codesec_scan_summary;

DROP TABLE IF EXISTS source_check_vuln;

DROP TABLE IF EXISTS source_check_license;

DROP TABLE IF EXISTS source_check_component;

DROP TABLE IF EXISTS source_check_scan_summary;

create table if not exists portal_user (
    `id` int unsigned not null AUTO_INCREMENT,
    `name` varchar(100) not null default '',
    `pwd` text not null,
    `role` varchar(50) not null default '',
    `mobile` varchar(100) not null default '',
    `comment` longtext not null,
    `status` varchar(30) not null default '',
    `source_check_token` text not null,
    `source_check_pwd` varchar(200) not null default '',
    `source_check_email` varchar(200) not null default '',
    `codesec_sk` text not null,
    `codesec_ak` text not null,
    `codesec_email` text not null,
    `codesec_pwd` varchar(100) not null default '',
    `token` text not null,
    `token_exp_at` bigint not null default '0',
    `created_at` bigint not null default '0',
    `updated_at` bigint not null default '0',
    `portal_email` varchar(100) not null default '',
    `tensor_email` varchar(100) not null default '',
    `tensor_pwd` varchar(200) not null default '',
    `deleted_at` bigint not null default '0',
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_account2` (`name`, `deleted_at`),
    UNIQUE KEY `idx_account3` (`portal_email`, `deleted_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

create table if not exists portal_project (
    id int unsigned auto_increment primary key,
    name varchar(100) not null default '',
    user_id int unsigned not null default 0,
    url varchar(200) not null default '',
    description longtext not null,
    git_type varchar(100) not null default '',
    token text not null,
    branch varchar(100) not null default '',
    tag varchar(100) not null default '' comment 'Git标签',
    uuid varchar(200) not null default '' comment '项目UUID',
    codesec_uuid varchar(200) not null default '' comment 'CodeSec项目UUID',
    codesec_app_id varchar(200) not null default '' comment 'CodeSec应用ID',
    codesec_org_id varchar(200) not null default '' comment 'CodeSec团队UUID',
    source_check_uuid varchar(200) not null default '' comment 'SourceCheck项目UUID',
    source_check_token text not null comment 'SourceCheck访问令牌',
    codesec_ak text not null comment 'CodeSec访问密钥',
    codesec_sk text not null comment 'CodeSec秘密密钥',
    codesec_scan_status varchar(50) not null default '' comment 'CodeSec扫描状态',
    codesec_high_risk varchar(50) not null default '' comment 'CodeSec最高风险等级',
    codesec_high_severity bigint not null default 0 comment 'CodeSec最高风险等级',
    codesec_scan_start_at bigint not null default 0 comment 'CodeSec扫描开始时间',
    codesec_scan_end_at bigint not null default 0 comment 'CodeSec结束开始时间',
    codesec_scan_msg TEXT not null comment 'CodeSec扫描消息',
    source_check_scan_status varchar(50) not null default '' comment 'SourceCheck扫描状态',
    source_check_high_risk varchar(50) not null default '' comment 'SourceCheck最高风险等级',
    source_check_high_severity BIGINT not null default 0 comment 'SourceCheck最高风险等级',
    source_check_check_no varchar(200) not null default '' comment 'SourceCheck检测编号',
    source_check_scan_start_at bigint not null default 0 comment 'SourceCheck扫描开始时间',
    source_check_scan_end_at bigint not null default 0 comment 'SourceCheck扫描结束时间',
    source_check_scan_msg TEXT not null comment 'SourceCheck扫描消息',
    risk_level varchar(50) not null default '' comment '项目风险级别：高、中、低、未知',
    last_scan_at bigint not null default 0 comment '最近扫描时间',
    updater varchar(200) not null default '' comment '最近一次更新人',
    created_at bigint not null default 0,
    updated_at bigint not null default 0,
    unique index idx_project_name (name, user_id, uuid),
    unique index  idx_project_uuid(uuid)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- CodeSec漏洞表
CREATE TABLE IF NOT EXISTS codesec_vuln (
    id BIGINT UNSIGNED not null AUTO_INCREMENT comment '主键ID',
    unique_id BIGINT UNSIGNED not null default 0 comment '唯一标识ID',
    project_uuid varchar(64) not null default '' comment '项目UUID',
    codesec_app_id varchar(64) not null default '' comment 'CodeSec应用ID',
    task_id varchar(64) not null default '' comment '任务ID',
    vul_id varchar(64) not null default '' comment '漏洞ID',
    vul_type_name varchar(255) not null default '' comment '漏洞类型名称',
    vul_type_id varchar(64) not null default '' comment '漏洞类型ID',
    language_name varchar(64) not null default '' comment '语言名称',
    vul_name varchar(255) not null default '' comment '漏洞名称',
    vul_data_id varchar(64) not null default '' comment '漏洞库信息ID',
    language_id int not null default 0 comment '语言类型ID',
    filename varchar(512) not null default '' comment '文件名',
    row_num varchar(32) not null default '' comment '文件行数',
    risk_id int not null default 0 comment '严重等级ID',
    risk_name varchar(64) not null default '' comment '严重等级名称',
    tag_id int not null default 0 comment '缺陷状态ID',
    tag_name varchar(64) not null default '' comment '缺陷状态名称',
    vul_flag varchar(64) not null default '' comment '缺陷跟踪类型',
    signer varchar(128) not null default '' comment '签名者',
    severity_int bigint not null default 0 comment '风险等级数值',
    severity varchar(32) not null default '' comment '风险等级英文',
    created_at BIGINT not null default 0 comment '创建时间',
    updated_at BIGINT not null default 0 comment '更新时间',
    PRIMARY KEY (id),
    INDEX idx_project_uuid (project_uuid, severity_int),
    unique INDEX idx_unique_id (unique_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci comment 'CodeSec漏洞表';

-- CodeSec扫描摘要表
CREATE TABLE IF NOT EXISTS codesec_scan_summary (
    id BIGINT UNSIGNED not null AUTO_INCREMENT comment '主键ID',
    unique_id BIGINT UNSIGNED not null default 0 comment '唯一标识ID',
    project_uuid varchar(64) not null default '' comment '项目UUID',
    codesec_uuid varchar(64) not null default '' comment 'CodeSec应用UUID',
    task_id varchar(64) not null default '' comment '任务ID',
    scan_status varchar(64) not null default '' comment '扫描状态',
    scan_msg TEXT not null comment '扫描消息',
    security_vul_num BIGINT not null default 0 comment '漏洞总数',
    code_security_weakness_num BIGINT not null default 0 comment '代码安全缺陷数',
    critical_num BIGINT not null default 0 comment '严重漏洞数',
    high_num BIGINT not null default 0 comment '高危漏洞数',
    medium_num BIGINT not null default 0 comment '中危漏洞数',
    low_num BIGINT not null default 0 comment '低危漏洞数',
    note_num BIGINT not null default 0 comment '建议漏洞数',
    new_discovery_num BIGINT not null default 0 comment '新发现漏洞数',
    repeat_num BIGINT not null default 0 comment '重复漏洞数',
    is_revise_num BIGINT not null default 0 comment '已修复漏洞数',
    library_num BIGINT not null default 0 comment '库漏洞数',
    cve_num BIGINT not null default 0 comment 'CVE漏洞数',
    cnnvd_num BIGINT not null default 0 comment 'CNNVD漏洞数',
    code_line_num BIGINT not null default 0 comment '代码行数',
    comment_lines BIGINT not null default 0 comment '注释行数',
    blank_lines BIGINT not null default 0 comment '空白行数',
    cyclomatic_complexity_num BIGINT not null default 0 comment '圈复杂度超标个数',
    repetitive_lines BIGINT not null default 0 comment '重复代码行数',
    file_num BIGINT not null default 0 comment '文件数',
    file_size BIGINT not null default 0 comment '文件总大小',
    language_id BIGINT not null default 0 comment '语言ID',
    language_name varchar(64) not null default '' comment '语言名称',
    git_branch varchar(128) not null default '' comment 'Git分支',
    git_commit_id varchar(64) not null default '' comment 'Git提交ID',
    git_extra_mark varchar(512) not null default '' comment 'Git额外标记',
    created_at BIGINT not null default 0 comment '创建时间',
    updated_at BIGINT not null default 0 comment '更新时间',
    PRIMARY KEY (id),
    index idx_project_task (project_uuid),
    UNIQUE INDEX idx_unique_id (unique_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci comment 'CodeSec扫描摘要表';

-- SourceCheck漏洞表
CREATE TABLE IF NOT EXISTS source_check_vuln (
    id BIGINT UNSIGNED not null AUTO_INCREMENT comment '主键ID',
    unique_id BIGINT UNSIGNED not null default 0 comment '唯一标识ID',
    project_uuid varchar(64) not null default '' comment '项目UUID',
    source_check_uuid varchar(64) not null default '' comment 'SourceCheck应用UUID',
    custom_sz_no varchar(128) not null default '' comment '自定义SZ编号',
    custom_cve_no varchar(128) not null default '' comment '自定义CVE编号',
    custom_cnnvd_no varchar(128) not null default '' comment '自定义CNNVD编号',
    affect_component_count BIGINT not null default 0 comment '影响组件数量',
    custom_cnvd_no varchar(128) not null default '' comment '自定义CNVD编号',
    grade varchar(32) not null default '' comment '风险等级',
    cwe varchar(128) not null default '' comment 'CWE编号',
    vulnerability_name varchar(512) not null default '' comment '漏洞名称',
    cwe_name varchar(512) not null default '' comment 'CWE名称',
    description TEXT not null comment '漏洞描述',
    release_date BIGINT not null default 0 comment '发布日期',
    severity_int bigint not null default 0 comment '风险等级数值',
    severity varchar(32) not null default '' comment '风险等级英文',
    created_at BIGINT not null default 0 comment '创建时间',
    updated_at BIGINT not null default 0 comment '更新时间',
    deleted_at BIGINT not null default 0 comment '删除时间',
    PRIMARY KEY (id),
    index uk_project_vul (project_uuid, severity_int),
    UNIQUE INDEX idx_unique_id (unique_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci comment 'SourceCheck漏洞表';

-- SourceCheck许可表
CREATE TABLE IF NOT EXISTS source_check_license (
    id BIGINT UNSIGNED not null AUTO_INCREMENT comment '主键ID',
    unique_id BIGINT UNSIGNED not null default 0 comment '唯一标识ID',
    project_uuid varchar(64) not null default '' comment '项目UUID',
    source_check_uuid varchar(64) not null default '' comment 'SourceCheck应用UUID',
    control_status BIGINT not null default 0 comment '黑白名单状态字典值',
    grade varchar(32) not null default '' comment '风险级别字典值',
    license_id varchar(64) not null default '' comment '许可简称',
    license_name varchar(256) not null default '' comment '许可全称',
    severity_int bigint not null default 0 comment '风险等级数值',
    severity varchar(32) not null default '' comment '风险等级英文',
    created_at BIGINT not null default 0 comment '创建时间',
    updated_at BIGINT not null default 0 comment '更新时间',
    deleted_at BIGINT not null default 0 comment '删除时间',
    PRIMARY KEY (id),
    index uk_project_vul (project_uuid, severity_int),
    UNIQUE INDEX idx_unique_id (unique_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci comment 'SourceCheck许可表';

-- SourceCheck组件表
CREATE TABLE IF NOT EXISTS source_check_component (
    id BIGINT UNSIGNED not null AUTO_INCREMENT comment '主键ID',
    unique_id BIGINT UNSIGNED not null default 0 comment '唯一标识ID',
    project_uuid varchar(64) not null default '' comment '项目UUID',
    source_check_uuid varchar(64) not null default '' comment 'SourceCheck应用UUID',
    component_id BIGINT not null default 0 comment '组件id',
    group_id varchar(256) not null default '' comment '组织',
    artifact_id varchar(256) not null default '' comment '组件名称',
    component_uuid varchar(128) not null default '' comment '组件唯一标识',
    control_status BIGINT not null default 0 comment '黑白名单状态字典值',
    control_status_name varchar(64) not null default '' comment '黑白名单字典值中文名',
    dep_rank varchar(32) not null default '' comment '依赖类型',
    dep_scope varchar(32) not null default '' comment '作用域',
    reference varchar(32) not null default '' comment '引用类型字典值',
    grade varchar(32) not null default '' comment '风险级别字典值',
    jar_info_add_from varchar(32) not null default '' comment '语言字典值',
    version varchar(128) not null default '' comment '版本',
    recommend_version varchar(128) not null default '' comment '推荐版本',
    app_version_id BIGINT not null default 0 comment '应用版本id',
    first_check_time BIGINT not null default 0 comment '第一次检测时间',
    last_check_time BIGINT not null default 0 comment '最后检测时间',
    source_info_list TEXT comment '来源信息列表(JSON)',
    origin varchar(512) not null default '' comment '来源',
    license_ids TEXT comment '许可名称列表(JSON)',
    grade_desc TEXT comment '风险描述',
    home_page varchar(512) not null default '' comment '主页',
    source_code varchar(512) not null default '' comment '源码',
    release_time BIGINT not null default 0 comment '发布时间',
    latest_version varchar(128) not null default '' comment '最新版本',
    private_public_status BIGINT not null default 0 comment '组件状态编码',
    private_public_status_name varchar(64) not null default '' comment '组件状态中文',
    classifier varchar(128) not null default '' comment 'classifier字符',
    project_white_control_status BIGINT not null default 0 comment '黑名单是否豁免',
    country varchar(64) not null default '' comment '所属国家',
    country_chinese_name varchar(64) not null default '' comment '所属国家的中文名称',
    virus_flag BIGINT not null default 0 comment '投毒组件标识',
    severity_int bigint not null default 0 comment '风险等级数值',
    severity varchar(32) not null default '' comment '风险等级英文',
    created_at BIGINT not null default 0 comment '创建时间',
    updated_at BIGINT not null default 0 comment '更新时间',
    deleted_at BIGINT not null default 0 comment '删除时间',
    PRIMARY KEY (id),
    index uk_project_vul (project_uuid, severity_int),
    UNIQUE INDEX idx_unique_id (unique_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci comment 'SourceCheck组件表';

-- SourceCheck扫描摘要表
CREATE TABLE IF NOT EXISTS source_check_scan_summary (
    id BIGINT UNSIGNED not null AUTO_INCREMENT comment '主键ID',
    unique_id BIGINT UNSIGNED not null default 0 comment '唯一标识ID',
    project_uuid varchar(64) not null default '' comment '项目UUID',
    source_check_uuid varchar(64) not null default '' comment 'SourceCheck应用UUID',
    check_no varchar(128) not null default '' comment '检测编号',
    scan_status varchar(64) not null default '' comment '扫描状态',
    scan_msg TEXT not null comment '扫描消息',
    component_count bigint not null default 0 comment '组件数量',
    vuln_count bigint not null default 0 comment '漏洞数量',
    license_count bigint not null default 0 comment '许可数量',
    high_risk_count bigint not null default 0 comment '高危数量',
    medium_risk_count bigint not null default 0 comment '中危数量',
    low_risk_count bigint not null default 0 comment '低危数量',
    critical_risk_count bigint not null default 0 comment '超危数量',
    scan_start_time bigint not null default 0 comment '扫描开始时间',
    scan_end_time bigint not null default 0 comment '扫描结束时间',
    scan_duration bigint not null default 0 comment '扫描时长（秒）',
    created_at BIGINT not null default 0 comment '创建时间',
    updated_at BIGINT not null default 0 comment '更新时间',
    PRIMARY KEY (id),
    index idx_project_app (project_uuid),
    UNIQUE INDEX idx_unique_id (unique_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci comment 'SourceCheck扫描摘要表';

alter table ivan_ci_scan_images
add COLUMN project_uuid varchar(200) NOT NULL default '' after id;

-- # 获取除portal_project和portal_use外的所有表名
-- TABLES=$(mysql  --host=172.21.2.229 --port=30036 -uroot -pMysql-ha@123 -N -e "SELECT table_name FROM information_schema.tables WHERE table_schema = 'ivan' AND table_name NOT IN ('portal_project', 'portal_use');")

-- mysqldump  --host=172.21.2.229 --port=30036 -uroot -pMysql-ha@123  --where="1 LIMIT 1000" ivan $TABLES > ivan_export.sql

-- # 获取所有以ivan_ci开头的表名
-- TABLES=$(mysql  --host=172.21.2.229 --port=30036 -uroot -pMysql-ha@123 -N -e "SELECT table_name FROM information_schema.tables WHERE table_schema = 'ivan' AND table_name LIKE '%export%';")

-- mysqldump  --host=172.21.2.229 --port=30036 -uroot -pMysql-ha@123 --where="1 LIMIT 1000" ivan $TABLES > ivan_exporte_tables_export.sql
-- alter table portal_project drop COLUMN codesec_high_severity;
-- alter table portal_project drop COLUMN source_check_high_severity;

-- alter table portal_project add COLUMN codesec_high_severity bigint   NOT NULL default 0;

-- alter table portal_project add COLUMN source_check_high_severity bigint   NOT NULL default 0;

-- mysqldump  --host=127.0.0.1 --port=3306 -uroot -proot  ivan > ivan.sql

