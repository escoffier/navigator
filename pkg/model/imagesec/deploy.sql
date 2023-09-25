drop table if exists ivan_scan_deploy_record;
drop table if exists ivan_scan_deploy_white_image;
drop table if exists ivan_scan_data_migrate;


create table if not exists ivan_scan_deploy_record
(
    id               bigint unsigned auto_increment,
    image_uuid       bigint unsigned not null default 0,
    image_unique_id  bigint unsigned not null default 0,
    image_name       varchar(500)    not null default '',
    host             varchar(500)    not null default '',
    repo             varchar(500)    not null default '',
    tag              varchar(500)    not null default '',
    image            longtext        not null,
    digest           varchar(100)    not null default '',
    action           varchar(100)    not null default '',
    vuln             longtext        not null,
    malware          longtext        not null,
    webshell         longtext        not null,
    `sensitive`      longtext        not null,
    pkg              longtext        not null,
    license          longtext        not null,
    env              longtext        not null,
    root_boot        longtext        not null,
    base_image       longtext        not null,
    trusted_image    longtext        not null,
    policy           longtext        not null,
    policy_unique_id varchar(500)    not null,
    hour             bigint unsigned not null default 0,
    day              bigint unsigned not null default 0,
    flag             bigint unsigned not null default 0,
    last_scan_at     bigint unsigned not null default 0,
    created_at       bigint unsigned not null default 0,
    updated_at       bigint unsigned not null default 0,

    primary key (id),
    index idx_image_uuid (image_uuid, flag),
    index idx_image_hour (hour, flag),
    index idx_image_day (day, flag),
    index idx_image_flag (flag, image_uuid),
    index idx_created_flag (created_at, flag)
);

create table if not exists ivan_scan_deploy_white_image
(
    id            bigint unsigned auto_increment,
    image_name    varchar(500)    not null default '',
    creator       varchar(300)    not null default '',
    updater       varchar(300)    not null default '',
    expiration_at bigint unsigned not null default 0,


    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index idx_image_name (image_name)
);

create table if not exists ivan_scan_data_migrate
(
    id           bigint unsigned auto_increment,
    soft_version varchar(100)    not null default '',
    model        varchar(50)     not null default '',
    last         longtext        not null,
    started_at   bigint unsigned not null default 0,
    finished_at  bigint unsigned not null default 0,


    created_at   bigint unsigned not null default 0,
    updated_at   bigint unsigned not null default 0,

    primary key (id),
    unique index idx_ver (soft_version, model, finished_at)
);

