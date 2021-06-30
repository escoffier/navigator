create table tensor_user
(
    id        bigserial not null
        constraint tensor_user_pkey primary key,
    username  text,
    pwd       text,
    salt      text,
    rule      text,
    module_id text,
    checked   bool,
    create_at bigint
);

alter table tensor_user owner to postgres;

create
index username on tensor_user (username);



create table tensor_email
(
    id        bigserial not null
        constraint tensor_email_pkey primary key,
    username  text,
    hash_code text,
    create_at bigint
);

alter table tensor_email owner to postgres;


create table tensor_image_list
(
    id               bigserial                not null
        constraint tensor_image_list_pkey primary key,
    url              text,
    full_repo_name   text,
    tags             text,
    digest           text,
    os               text,
    size             bigint,
    library          text,
    complete_time    text,
    on_line_count    bigint default 0,
    registry_id      bigint,
    first_push_time  timestamp with time zone,
    last_push_time   timestamp with time zone not null,
    last_pull_time   timestamp with time zone,
    manifest_v1_json jsonb,
    manifest_v2_json jsonb,
    config_json      jsonb,
    created_at       timestamp with time zone not null,
    updated_at       timestamp with time zone not null,
    status           bigint default 0
);

alter table tensor_image_list owner to postgres;

create
index "idx:digest_library" on tensor_image_list (digest, library);



create table scan_images
(
    id                      bigserial not null
        constraint scan_images_pkey primary key,

    image_id                bigint,
    risk_score              numeric,
    vuln_info_json          jsonb,
    pkg_info_json           jsonb,
    malicious_info_json     jsonb,
    sensitive_file_json     jsonb,
    per_layer_report_json   jsonb,
    overall_severity        text,
    overall_severity_int    bigint,
    severity_histogram_json jsonb,
    scan_task_id            text,
    status                  text,
    message                 text,
    started_at              bigint,
    finish_at               bigint,
    created_at              timestamp with time zone,
    updated_at              timestamp with time zone,
    deleted_at              bigint
);

alter table scan_images owner to postgres;

create
index idx_image_id on scan_images (image_id);



create table scan_layers
(
    id                  bigserial not null
        constraint scan_layers_pkey primary key,

    image_id            bigint,
    layer_digest        text,
    vuln_info_json      jsonb,
    pkg_info_json       jsonb,
    malicious_info_json jsonb,
    sensitive_file_json jsonb,
    is_basic            bigint,
    created_at          timestamp with time zone,
    updated_at          timestamp with time zone,
    deleted_at          bigint
);

alter table scan_layers owner to postgres;

create
index idx_digest on scan_layers (layer_digest);


create table vuln_images
(
    id         bigserial not null
        constraint vuln_images_pkey primary key,
    image_id   bigint,
    vuln_name  text,

    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at bigint
);

alter table vuln_images owner to postgres;

create
index idx_image_id on vuln_images (image_id);


create table vulns
(
    id            bigserial not null
        constraint vulns_pkey primary key,
    name          text,
    namespace     text,
    description   text,
    link_json     jsonb,
    severity      text,
    severity_int  bigint,
    metadata_json jsonb,
    pkg_name      text,
    pkg_version   text,
    fixed_by      text,
    extra_info    jsonb,
    created_at    timestamp with time zone,
    updated_at    timestamp with time zone,
    deleted_at    bigint
);

alter table vulns
    owner to postgres;

create
index idx_vulns_name on vulns (name);

create table registries
(
    id          bigserial not null
        constraint registries_pkey primary key,
    url         text,
    username    text,
    password    bytea,
    tls         bigint,
    token       text,
    description text,
    api_version text,
    created_at  timestamp with time zone,
    updated_at  timestamp with time zone,
    deleted_at  bigint
);

alter table registries owner to postgres;

create table image_relate
(
    id           bigserial not null
        constraint image_relate_pkey primary key,
    digest       text,
    library      text,
    container_id text
);

alter table image_relate owner to postgres;

create
unique index digest_library on image_relate (digest, library, container_id);


-- https://www.postgresqltutorial.com/postgresql-char-varchar-text/ 推荐使用text

