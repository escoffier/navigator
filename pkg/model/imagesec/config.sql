drop table if exists ivan_scan_sensitive_rule;
drop table if exists ivan_scan_image_config;

create table if not exists ivan_scan_sensitive_rule
(
    id            bigint unsigned auto_increment,
    `value`       varchar(500)    not null default '',
    `description` text            not null,
    rule_type     varchar(500)    not null default '',
    is_default    boolean         not null default false,
    `enable`      boolean         not null default false,
    updater       varchar(500)    not null default '',
    creator       varchar(500)    not null default '',

    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,
    primary key (id),
    unique index idx_sens_rule (`value`)
);



create table if not exists ivan_scan_image_config
(
    id            bigint unsigned auto_increment,
    `config_type` varchar(100)    not null default '',
    `config_data` longtext        not null,
    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,
    primary key (id),
    unique index idx_sens_rule (`config_type`)
);