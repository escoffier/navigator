drop table if exists ivan_image_vuln_detect;
drop table if exists ivan_image_sensitive_detect;
drop table if exists ivan_image_malware_detect;
drop table if exists ivan_image_pkg_detect;
drop table if exists ivan_image_license_detect;
drop table if exists ivan_image_webshell_detect;
drop table if exists ivan_image_root_detect;
drop table if exists ivan_image_env_detect;
drop table if exists ivan_image_detect_brief;



create table if not exists ivan_image_vuln_detect
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

create table if not exists ivan_image_sensitive_detect
(
    id            bigint unsigned auto_increment,
    flag          bigint unsigned not null default 0,
    unique_target bigint unsigned not null default 0,
    image_unique_id      bigint unsigned not null default 0,
    policy_id     bigint unsigned not null default 0,

    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_malware_detect
(
    id            bigint unsigned auto_increment,
    flag          bigint unsigned not null default 0,
    unique_target bigint unsigned not null default 0,
    image_unique_id      bigint unsigned not null default 0,
    policy_id     bigint unsigned not null default 0,

    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_pkg_detect
(
    id            bigint unsigned auto_increment,
    flag          bigint unsigned not null default 0,
    unique_target bigint unsigned not null default 0,
    image_unique_id      bigint unsigned not null default 0,
    policy_id     bigint unsigned not null default 0,

    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_license_detect
(
    id            bigint unsigned auto_increment,
    flag          bigint unsigned not null default 0,
    unique_target bigint unsigned not null default 0,
    image_unique_id      bigint unsigned not null default 0,
    policy_id     bigint unsigned not null default 0,

    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_webshell_detect
(
    id            bigint unsigned auto_increment,
    flag          bigint unsigned not null default 0,
    unique_target bigint unsigned not null default 0,
    image_unique_id      bigint unsigned not null default 0,
    policy_id     bigint unsigned not null default 0,

    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_root_detect
(
    id            bigint unsigned auto_increment,
    flag          bigint unsigned not null default 0,
    unique_target bigint unsigned not null default 0,
    image_unique_id      bigint unsigned not null default 0,
    policy_id     bigint unsigned not null default 0,

    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);

create table if not exists ivan_image_env_detect
(
    id            bigint unsigned auto_increment,
    flag          bigint unsigned not null default 0,
    unique_target bigint unsigned not null default 0,
    image_unique_id      bigint unsigned not null default 0,
    policy_id     bigint unsigned not null default 0,

    created_at    bigint unsigned not null default 0,
    updated_at    bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, unique_target, policy_id)
);


create table if not exists ivan_image_detect_brief
(
    id         bigint unsigned auto_increment,
    flag       bigint unsigned not null default 0,
    image_unique_id   bigint unsigned not null default 0,
    policy_id  bigint unsigned not null default 0,
    policy     longtext        not null,
    created_at bigint unsigned not null default 0,
    updated_at bigint unsigned not null default 0,

    primary key (id),
    unique index unq_idx_image (image_unique_id, policy_id)
);

