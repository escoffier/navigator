package main

const (
	sql = `--
-- PostgreSQL database dump
--

-- Dumped from database version 12.8
-- Dumped by pg_dump version 12.8

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: apparmor_profile_data; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.apparmor_profile_data (
    apparmor_profile_id bigint,
    file text,
    access text
);


ALTER TABLE public.apparmor_profile_data OWNER TO postgres;

--
-- Name: apparmor_profiles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.apparmor_profiles (
    security_policy_id bigint,
    id bigint NOT NULL,
    enabled boolean,
    timeframe bigint,
    training_status text,
    start_training_time timestamp with time zone,
    stop_training_time timestamp with time zone,
    abort_training_time timestamp with time zone,
    suspend_training_time timestamp with time zone,
    resume_training_time timestamp with time zone,
    elapsed_time bigint,
    training_timeout bigint,
    training_start_whitelist_option text
);


ALTER TABLE public.apparmor_profiles OWNER TO postgres;

--
-- Name: apparmor_profiles_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.apparmor_profiles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.apparmor_profiles_id_seq OWNER TO postgres;

--
-- Name: apparmor_profiles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.apparmor_profiles_id_seq OWNED BY public.apparmor_profiles.id;


--
-- Name: association_events; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.association_events (
    id integer NOT NULL,
    association_type text,
    content jsonb,
    severity smallint,
    rule_module character varying(32),
    rule_category character varying(32),
    rule_name character varying(255),
    created_at timestamp(3) without time zone,
    updated_at timestamp(3) without time zone
);


ALTER TABLE public.association_events OWNER TO postgres;

--
-- Name: association_events_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.association_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.association_events_id_seq OWNER TO postgres;

--
-- Name: association_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.association_events_id_seq OWNED BY public.association_events.id;


--
-- Name: attck_rule_datas; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.attck_rule_datas (
    id integer NOT NULL,
    content bytea,
    version text,
    username text,
    created_at timestamp without time zone
);


ALTER TABLE public.attck_rule_datas OWNER TO postgres;

--
-- Name: attck_rule_datas_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.attck_rule_datas_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.attck_rule_datas_id_seq OWNER TO postgres;

--
-- Name: attck_rule_datas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.attck_rule_datas_id_seq OWNED BY public.attck_rule_datas.id;


--
-- Name: attck_rule_mask_version; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.attck_rule_mask_version (
    version bigint
);


ALTER TABLE public.attck_rule_mask_version OWNER TO postgres;

--
-- Name: attck_rule_masks; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.attck_rule_masks (
    id integer NOT NULL,
    name text
);


ALTER TABLE public.attck_rule_masks OWNER TO postgres;

--
-- Name: attck_rule_masks_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.attck_rule_masks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.attck_rule_masks_id_seq OWNER TO postgres;

--
-- Name: attck_rule_masks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.attck_rule_masks_id_seq OWNED BY public.attck_rule_masks.id;


--
-- Name: command_whitelist_profile_data; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.command_whitelist_profile_data (
    command_whitelist_profile_id bigint,
    command text,
    working_directory text
);


ALTER TABLE public.command_whitelist_profile_data OWNER TO postgres;

--
-- Name: command_whitelist_profiles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.command_whitelist_profiles (
    security_policy_id bigint,
    id bigint NOT NULL,
    enabled boolean,
    timeframe bigint,
    training_status text,
    start_training_time timestamp with time zone,
    stop_training_time timestamp with time zone,
    abort_training_time timestamp with time zone,
    suspend_training_time timestamp with time zone,
    resume_training_time timestamp with time zone,
    elapsed_time bigint,
    training_timeout bigint,
    training_start_whitelist_option text
);


ALTER TABLE public.command_whitelist_profiles OWNER TO postgres;

--
-- Name: command_whitelist_profiles_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.command_whitelist_profiles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.command_whitelist_profiles_id_seq OWNER TO postgres;

--
-- Name: command_whitelist_profiles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.command_whitelist_profiles_id_seq OWNED BY public.command_whitelist_profiles.id;


--
-- Name: cron_scan_task; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.cron_scan_task (
    created_at bigint,
    cron_time text,
    check_type text,
    cluster_id text,
    cron_id bigint
);


ALTER TABLE public.cron_scan_task OWNER TO postgres;

--
-- Name: drift_profiles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.drift_profiles (
    security_policy_id bigint,
    id bigint NOT NULL,
    enabled boolean
);


ALTER TABLE public.drift_profiles OWNER TO postgres;

--
-- Name: drift_profiles_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.drift_profiles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.drift_profiles_id_seq OWNER TO postgres;

--
-- Name: drift_profiles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.drift_profiles_id_seq OWNED BY public.drift_profiles.id;


--
-- Name: event_notify_settings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.event_notify_settings (
    email_notification boolean,
    emails text[],
    threshold_severity bigint
);


ALTER TABLE public.event_notify_settings OWNER TO postgres;

--
-- Name: gc_tasks; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.gc_tasks (
    id integer NOT NULL,
    hash text,
    category text,
    status text,
    created_at timestamp without time zone,
    finished_at timestamp without time zone
);


ALTER TABLE public.gc_tasks OWNER TO postgres;

--
-- Name: gc_tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.gc_tasks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.gc_tasks_id_seq OWNER TO postgres;

--
-- Name: gc_tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.gc_tasks_id_seq OWNED BY public.gc_tasks.id;


--
-- Name: image_relate; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.image_relate (
    id bigint NOT NULL,
    digest character varying(100),
    library character varying(100),
    container_id character varying(100)
);


ALTER TABLE public.image_relate OWNER TO postgres;

--
-- Name: image_relate_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.image_relate_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.image_relate_id_seq OWNER TO postgres;

--
-- Name: image_relate_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.image_relate_id_seq OWNED BY public.image_relate.id;


--
-- Name: image_rsa; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.image_rsa (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    rsa_id character(14),
    name character varying(50),
    private_key_digest character(64),
    public_key text NOT NULL,
    registry text DEFAULT ''::text,
    match_rule text DEFAULT ''::text,
    comment character varying(150) DEFAULT ''::character varying
);


ALTER TABLE public.image_rsa OWNER TO postgres;

--
-- Name: COLUMN image_rsa.rsa_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.image_rsa.rsa_id IS '唯一的ID';


--
-- Name: COLUMN image_rsa.name; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.image_rsa.name IS '名字';


--
-- Name: COLUMN image_rsa.private_key_digest; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.image_rsa.private_key_digest IS '私钥的sha256值';


--
-- Name: COLUMN image_rsa.public_key; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.image_rsa.public_key IS '公钥的内容';


--
-- Name: COLUMN image_rsa.registry; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.image_rsa.registry IS '适用的仓库';


--
-- Name: COLUMN image_rsa.match_rule; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.image_rsa.match_rule IS '匹配规则';


--
-- Name: COLUMN image_rsa.comment; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.image_rsa.comment IS '说明';


--
-- Name: image_rsa_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.image_rsa_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.image_rsa_id_seq OWNER TO postgres;

--
-- Name: image_rsa_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.image_rsa_id_seq OWNED BY public.image_rsa.id;


--
-- Name: image_whitelist; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.image_whitelist (
    id bigint NOT NULL,
    library text,
    full_repo_name text,
    tag text,
    created_at timestamp with time zone,
    digest text
);


ALTER TABLE public.image_whitelist OWNER TO postgres;

--
-- Name: image_whitelist_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.image_whitelist_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.image_whitelist_id_seq OWNER TO postgres;

--
-- Name: image_whitelist_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.image_whitelist_id_seq OWNED BY public.image_whitelist.id;


--
-- Name: immune_policies; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.immune_policies (
    name character varying(128) NOT NULL,
    description character varying(255) DEFAULT ''::character varying,
    kind smallint NOT NULL,
    cluster_key character varying(128) NOT NULL,
    resource_uuid bigint NOT NULL,
    resource_version bigint DEFAULT 0 NOT NULL,
    decision smallint NOT NULL,
    status smallint NOT NULL,
    creator character varying(128) NOT NULL,
    updater character varying(128) NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    id bigint NOT NULL
);


ALTER TABLE public.immune_policies OWNER TO postgres;

--
-- Name: immune_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.immune_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.immune_policies_id_seq OWNER TO postgres;

--
-- Name: immune_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.immune_policies_id_seq OWNED BY public.immune_policies.id;


--
-- Name: immune_profiles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.immune_profiles (
    uuid bigint NOT NULL,
    policy_id bigint NOT NULL,
    container_name character varying(128) NOT NULL,
    value bytea NOT NULL,
    status smallint NOT NULL,
    creator character varying(128) NOT NULL,
    created_at timestamp without time zone NOT NULL
);


ALTER TABLE public.immune_profiles OWNER TO postgres;

--
-- Name: immune_tasks; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.immune_tasks (
    resource_uuid bigint NOT NULL,
    pod_name character varying(128),
    container_id character varying(128),
    policy_kind smallint NOT NULL,
    terminated_at timestamp without time zone NOT NULL,
    state smallint NOT NULL,
    status smallint NOT NULL,
    creator character varying(128) NOT NULL,
    updater character varying(128) NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    id bigint NOT NULL
);


ALTER TABLE public.immune_tasks OWNER TO postgres;

--
-- Name: immune_tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.immune_tasks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.immune_tasks_id_seq OWNER TO postgres;

--
-- Name: immune_tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.immune_tasks_id_seq OWNED BY public.immune_tasks.id;


--
-- Name: kube_hunter_records; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.kube_hunter_records (
    uuid character varying(32) NOT NULL,
    username character varying(128),
    cluster character varying(100),
    status integer,
    meta_info bytea,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


ALTER TABLE public.kube_hunter_records OWNER TO postgres;

--
-- Name: ldap_groups; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ldap_groups (
    id integer NOT NULL,
    name character varying(255),
    role character varying(32),
    modules character varying(255)
);


ALTER TABLE public.ldap_groups OWNER TO postgres;

--
-- Name: ldap_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.ldap_groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.ldap_groups_id_seq OWNER TO postgres;

--
-- Name: ldap_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.ldap_groups_id_seq OWNED BY public.ldap_groups.id;


--
-- Name: migrations_record; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.migrations_record (
    version bigint NOT NULL,
    dirty boolean NOT NULL
);


ALTER TABLE public.migrations_record OWNER TO postgres;

--
-- Name: openapi_auth_token; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.openapi_auth_token (
    id integer NOT NULL,
    token text,
    username text,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    status smallint
);


ALTER TABLE public.openapi_auth_token OWNER TO postgres;

--
-- Name: openapi_auth_token_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.openapi_auth_token_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.openapi_auth_token_id_seq OWNER TO postgres;

--
-- Name: openapi_auth_token_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.openapi_auth_token_id_seq OWNED BY public.openapi_auth_token.id;


--
-- Name: palace_assoc_graph_events; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.palace_assoc_graph_events (
    id bigint NOT NULL,
    association_kind character varying(256) NOT NULL,
    locations jsonb NOT NULL,
    events_num bigint DEFAULT 0,
    nodes_num bigint DEFAULT 0,
    severity smallint DEFAULT 0,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


ALTER TABLE public.palace_assoc_graph_events OWNER TO postgres;

--
-- Name: palace_assoc_graph_events_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.palace_assoc_graph_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.palace_assoc_graph_events_id_seq OWNER TO postgres;

--
-- Name: palace_assoc_graph_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.palace_assoc_graph_events_id_seq OWNED BY public.palace_assoc_graph_events.id;


--
-- Name: palace_assoc_links; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.palace_assoc_links (
    uuid bigint NOT NULL,
    aggr_evt_id bigint NOT NULL,
    src_cluster_key character varying(64) NOT NULL,
    src_loc_type character varying(64) NOT NULL,
    src_loc_expr character varying(256) NOT NULL,
    dest_cluster_key character varying(64) NOT NULL,
    dest_loc_type character varying(64) NOT NULL,
    dest_loc_expr character varying(256) NOT NULL,
    context jsonb,
    created_at timestamp without time zone
);


ALTER TABLE public.palace_assoc_links OWNER TO postgres;

--
-- Name: palace_evt_signal_assocs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.palace_evt_signal_assocs (
    uuid bigint NOT NULL,
    aggr_evt_id bigint NOT NULL,
    aggr_key character varying(256) NOT NULL,
    signal_id character varying(256) NOT NULL,
    created_at timestamp without time zone
);


ALTER TABLE public.palace_evt_signal_assocs OWNER TO postgres;

--
-- Name: processingcenter_actions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.processingcenter_actions (
    id integer NOT NULL,
    object text,
    record_id character varying(32),
    operation character varying(32),
    creator character varying(32),
    created_at timestamp without time zone
);


ALTER TABLE public.processingcenter_actions OWNER TO postgres;

--
-- Name: processingcenter_actions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.processingcenter_actions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.processingcenter_actions_id_seq OWNER TO postgres;

--
-- Name: processingcenter_actions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.processingcenter_actions_id_seq OWNED BY public.processingcenter_actions.id;


--
-- Name: registries; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.registries (
    id bigint NOT NULL,
    name text,
    reg_type text,
    url text,
    username text,
    password bytea,
    description text,
    use_type bigint,
    sync_interval bigint,
    last_sync_at bigint DEFAULT 0,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at bigint DEFAULT 0
);


ALTER TABLE public.registries OWNER TO postgres;

--
-- Name: registries_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.registries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.registries_id_seq OWNER TO postgres;

--
-- Name: registries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.registries_id_seq OWNED BY public.registries.id;


--
-- Name: reject_policy; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.reject_policy (
    id bigint NOT NULL,
    name text,
    library_json jsonb,
    comment text,
    operator text,
    vuln_score bigint,
    vuln_level text,
    sensitive_file_policy text,
    malicious_policy text,
    cicd_enable boolean,
    k8s_enable boolean,
    mode text,
    online_monitor boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    enable boolean,
    is_global boolean,
    deleted_at bigint,
    web_shell_score bigint,
    base_image_policy text,
    web_shell_policy text,
    vuln_policy text,
    trusted_image_policy text DEFAULT 'alarm'::text,
    privileged_boot_policy text DEFAULT 'alarm'::text,
    sensitive_file text DEFAULT ''::text,
    envs text DEFAULT ''::text,
    env_policy text DEFAULT ''::text
);


ALTER TABLE public.reject_policy OWNER TO postgres;

--
-- Name: reject_policy_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.reject_policy_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.reject_policy_id_seq OWNER TO postgres;

--
-- Name: reject_policy_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.reject_policy_id_seq OWNED BY public.reject_policy.id;


--
-- Name: reject_record; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.reject_record (
    id bigint NOT NULL,
    library text,
    full_repo_name text,
    tag text,
    reject_detail text,
    reject_reason_json jsonb,
    vuln_score bigint,
    vuln_level text,
    digest text,
    reject_at timestamp with time zone,
    created_at timestamp with time zone,
    deleted_at bigint
);


ALTER TABLE public.reject_record OWNER TO postgres;

--
-- Name: reject_record_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.reject_record_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.reject_record_id_seq OWNER TO postgres;

--
-- Name: reject_record_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.reject_record_id_seq OWNED BY public.reject_record.id;


--
-- Name: reject_vuln; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.reject_vuln (
    id bigint NOT NULL,
    reject_policy_id bigint,
    library text,
    name text,
    reject_policy text,
    created_at timestamp with time zone
);


ALTER TABLE public.reject_vuln OWNER TO postgres;

--
-- Name: reject_vuln_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.reject_vuln_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.reject_vuln_id_seq OWNER TO postgres;

--
-- Name: reject_vuln_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.reject_vuln_id_seq OWNED BY public.reject_vuln.id;


--
-- Name: report_records; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.report_records (
    uuid character varying(32) NOT NULL,
    template_id integer,
    start_timestamp bigint,
    end_timestamp bigint,
    status smallint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    content bytea
);


ALTER TABLE public.report_records OWNER TO postgres;

--
-- Name: report_task_templates; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.report_task_templates (
    id integer NOT NULL,
    name character varying(100),
    type character varying(32),
    clusters text,
    categories character varying(255),
    emails text,
    description character varying(255),
    cycle_day integer,
    start_timestamp bigint,
    end_timestamp bigint,
    latest_generate_timestamp bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


ALTER TABLE public.report_task_templates OWNER TO postgres;

--
-- Name: report_task_templates_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.report_task_templates_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.report_task_templates_id_seq OWNER TO postgres;

--
-- Name: report_task_templates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.report_task_templates_id_seq OWNED BY public.report_task_templates.id;


--
-- Name: rules; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.rules (
    id integer NOT NULL,
    name character varying(255),
    module character varying(32),
    category character varying(32),
    description text,
    severity smallint,
    custom_kv jsonb,
    multi_language jsonb,
    status smallint
);


ALTER TABLE public.rules OWNER TO postgres;

--
-- Name: rules_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.rules_id_seq OWNER TO postgres;

--
-- Name: rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.rules_id_seq OWNED BY public.rules.id;


--
-- Name: scan_bench_history; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.scan_bench_history (
    task_id character varying(64) NOT NULL,
    check_type character varying(10),
    cluster_key character varying(64),
    cluster_name character varying(64),
    operator character varying(100),
    state smallint,
    suc_node smallint,
    fail_node smallint,
    created_at bigint,
    finished_at bigint
);


ALTER TABLE public.scan_bench_history OWNER TO postgres;

--
-- Name: scan_bench_result; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.scan_bench_result (
    id bigint NOT NULL,
    task_id character varying(64),
    check_type character varying(10),
    node_name character varying(100),
    cluster_key character varying(64),
    policy_id character varying(120),
    state text,
    actual_value text,
    remediation_en text,
    remediation_zh text,
    create_at bigint,
    status integer
);


ALTER TABLE public.scan_bench_result OWNER TO postgres;

--
-- Name: scan_bench_result_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.scan_bench_result_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.scan_bench_result_id_seq OWNER TO postgres;

--
-- Name: scan_bench_result_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.scan_bench_result_id_seq OWNED BY public.scan_bench_result.id;


--
-- Name: scan_export_task; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.scan_export_task (
    status smallint,
    check_type character varying(10),
    cluster_id character varying(64),
    task_id character varying(64),
    filename character varying(100),
    username text,
    created_at bigint,
    finished_at bigint,
    content bytea
);


ALTER TABLE public.scan_export_task OWNER TO postgres;

--
-- Name: scan_images; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.scan_images (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at bigint,
    image_id bigint,
    risk_score numeric,
    vuln_score numeric,
    sensitive_score numeric,
    virus_score numeric,
    webshell_score numeric,
    vuln_info_json jsonb,
    pkg_info_json jsonb,
    malicious_info_json jsonb,
    webshell_info_json jsonb,
    sensitive_file_json jsonb,
    per_layer_report_json jsonb,
    overall_severity text,
    overall_severity_int bigint,
    severity_histogram_json jsonb,
    scan_task_id text,
    status text,
    message text,
    started_at bigint,
    finish_at bigint,
    has_fixed_vuln bigint,
    license_info_json jsonb,
    software_json jsonb,
    scan_enable_collection_json text,
    env_json jsonb
);


ALTER TABLE public.scan_images OWNER TO postgres;

--
-- Name: scan_images_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.scan_images_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.scan_images_id_seq OWNER TO postgres;

--
-- Name: scan_images_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.scan_images_id_seq OWNED BY public.scan_images.id;


--
-- Name: scan_layers; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.scan_layers (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at bigint,
    image_id bigint,
    layer_digest text,
    vuln_info_json jsonb,
    pkg_info_json jsonb,
    malicious_info_json jsonb,
    webshell_info_json jsonb,
    sensitive_file_json jsonb,
    is_basic bigint
);


ALTER TABLE public.scan_layers OWNER TO postgres;

--
-- Name: scan_layers_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.scan_layers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.scan_layers_id_seq OWNER TO postgres;

--
-- Name: scan_layers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.scan_layers_id_seq OWNED BY public.scan_layers.id;


--
-- Name: scan_node_record; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.scan_node_record (
    task_id character varying(64),
    check_type character varying(10),
    cluster_key character varying(64),
    operator character varying(100),
    node_name character varying(100),
    state integer,
    message text,
    created_at bigint,
    finished_at bigint,
    auto_variate text,
    namespace character varying(100),
    job_name character varying(100)
);


ALTER TABLE public.scan_node_record OWNER TO postgres;

--
-- Name: scan_policy_detail; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.scan_policy_detail (
    policy_id character varying(120),
    check_type character varying(10),
    status integer,
    creator text,
    created_at bigint,
    updater text,
    updated_at bigint,
    title_en text,
    title_zh text,
    detail_en text,
    detail_zh text,
    remediation_en text,
    remediation_zh text,
    expeced_result text,
    audit text,
    audit_config text
);


ALTER TABLE public.scan_policy_detail OWNER TO postgres;

--
-- Name: seccomp_profile_data; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.seccomp_profile_data (
    seccomp_profile_id bigint,
    syscall text
);


ALTER TABLE public.seccomp_profile_data OWNER TO postgres;

--
-- Name: seccomp_profiles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.seccomp_profiles (
    security_policy_id bigint,
    id bigint NOT NULL,
    enabled boolean,
    timeframe bigint,
    training_status text,
    start_training_time timestamp with time zone,
    stop_training_time timestamp with time zone,
    abort_training_time timestamp with time zone,
    suspend_training_time timestamp with time zone,
    resume_training_time timestamp with time zone,
    elapsed_time bigint,
    training_timeout bigint,
    training_start_whitelist_option text
);


ALTER TABLE public.seccomp_profiles OWNER TO postgres;

--
-- Name: seccomp_profiles_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.seccomp_profiles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.seccomp_profiles_id_seq OWNER TO postgres;

--
-- Name: seccomp_profiles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.seccomp_profiles_id_seq OWNED BY public.seccomp_profiles.id;


--
-- Name: security_policies; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.security_policies (
    id bigint NOT NULL,
    mode text,
    name text,
    description text,
    active boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    author text,
    updated_by text,
    resource_image_change_action text
);


ALTER TABLE public.security_policies OWNER TO postgres;

--
-- Name: security_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.security_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.security_policies_id_seq OWNER TO postgres;

--
-- Name: security_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.security_policies_id_seq OWNED BY public.security_policies.id;


--
-- Name: security_policy_resources; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.security_policy_resources (
    security_policy_id bigint,
    id bigint NOT NULL,
    cluster text,
    name text,
    kind text,
    namespace text,
    container_name text,
    image_registry text,
    image_name text,
    image_tag text
);


ALTER TABLE public.security_policy_resources OWNER TO postgres;

--
-- Name: security_policy_resources_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.security_policy_resources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.security_policy_resources_id_seq OWNER TO postgres;

--
-- Name: security_policy_resources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.security_policy_resources_id_seq OWNED BY public.security_policy_resources.id;


--
-- Name: tensor_apis; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_apis (
    id bigint NOT NULL,
    cluster character varying(100),
    namespace character varying(100),
    pod_name character varying(100),
    ip character varying(20),
    port character varying(20),
    path character varying(1000),
    scheme character varying(10),
    content_type character varying(50),
    method character varying(10),
    scan_result text,
    status smallint,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    params character varying(100),
    resource character varying(100),
    kind character varying(100)
);


ALTER TABLE public.tensor_apis OWNER TO postgres;

--
-- Name: tensor_apis_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_apis_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_apis_id_seq OWNER TO postgres;

--
-- Name: tensor_apis_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_apis_id_seq OWNED BY public.tensor_apis.id;


--
-- Name: tensor_clusters; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_clusters (
    key text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    creator text,
    updater text,
    status smallint DEFAULT 0,
    name text,
    description text,
    api_server_addr text,
    certificate_auth_data text,
    secret_token text,
    secret_namespace text,
    cluster_type text,
    worker_namespace text,
    label_inited boolean DEFAULT false,
    client_cert_data text,
    client_key_data text
);


ALTER TABLE public.tensor_clusters OWNER TO postgres;

--
-- Name: tensor_configs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_configs (
    key text NOT NULL,
    config bytea,
    creator text,
    updater text,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    status integer
);


ALTER TABLE public.tensor_configs OWNER TO postgres;

--
-- Name: tensor_containers; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_containers (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    status smallint DEFAULT 0,
    name text,
    namespace text,
    cluster_key text,
    resource_kind text,
    resource_name text,
    image text,
    spec jsonb,
    ports jsonb,
    image_pull_policy jsonb,
    security_context jsonb,
    image_uuid bigint,
    type character varying(64),
    web_frame_version character varying(128) DEFAULT NULL::character varying,
    app_type character varying(128) DEFAULT NULL::character varying,
    app_target_name character varying(128) DEFAULT NULL::character varying,
    app_target_version character varying(128) DEFAULT NULL::character varying
);


ALTER TABLE public.tensor_containers OWNER TO postgres;

--
-- Name: tensor_email; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_email (
    id integer NOT NULL,
    hash_code character varying(64),
    create_at bigint,
    username text
);


ALTER TABLE public.tensor_email OWNER TO postgres;

--
-- Name: tensor_email_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_email_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_email_id_seq OWNER TO postgres;

--
-- Name: tensor_email_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_email_id_seq OWNED BY public.tensor_email.id;


--
-- Name: tensor_image_list; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_image_list (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    url text,
    full_repo_name text,
    tags text,
    digest text,
    os text,
    size bigint,
    library text,
    complete_time text,
    on_line_count bigint DEFAULT 0,
    status bigint DEFAULT 0,
    registry_id bigint,
    first_push_time timestamp with time zone,
    last_push_time timestamp with time zone NOT NULL,
    last_pull_time timestamp with time zone,
    manifest_v1_json jsonb,
    manifest_v2_json jsonb,
    config_json jsonb,
    from_type bigint DEFAULT 1,
    layers text,
    image_type bigint DEFAULT 0,
    image_uuid bigint,
    node_ip text,
    node_hostname text,
    is_reinforce bigint,
    privileged_boot bigint,
    project text,
    repo_name text
);


ALTER TABLE public.tensor_image_list OWNER TO postgres;

--
-- Name: tensor_image_list_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_image_list_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_image_list_id_seq OWNER TO postgres;

--
-- Name: tensor_image_list_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_image_list_id_seq OWNED BY public.tensor_image_list.id;


--
-- Name: tensor_microseg_logic_clusters; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_microseg_logic_clusters (
    id bigint NOT NULL,
    name character varying(100),
    cluster character varying(100),
    tenants character varying(100) DEFAULT '[]'::character varying,
    nodes character varying(1024),
    status smallint,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.tensor_microseg_logic_clusters OWNER TO postgres;

--
-- Name: tensor_microseg_logic_clusters_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_microseg_logic_clusters_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_microseg_logic_clusters_id_seq OWNER TO postgres;

--
-- Name: tensor_microseg_logic_clusters_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_microseg_logic_clusters_id_seq OWNED BY public.tensor_microseg_logic_clusters.id;


--
-- Name: tensor_microseg_nsgrps; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_microseg_nsgrps (
    id bigint NOT NULL,
    uuid bigint NOT NULL,
    name character varying(100),
    cluster character varying(100),
    policy_namespace character varying(100),
    namespaces character varying(1024),
    status smallint,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.tensor_microseg_nsgrps OWNER TO postgres;

--
-- Name: tensor_microseg_nsgrps_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_microseg_nsgrps_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_microseg_nsgrps_id_seq OWNER TO postgres;

--
-- Name: tensor_microseg_nsgrps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_microseg_nsgrps_id_seq OWNED BY public.tensor_microseg_nsgrps.id;


--
-- Name: tensor_microseg_policies; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_microseg_policies (
    name character varying(64) NOT NULL,
    status smallint,
    cluster character varying(100),
    namespace character varying(100),
    allow_external boolean DEFAULT false,
    revision bigint,
    type character varying(20) NOT NULL,
    trusted boolean DEFAULT false,
    creator character varying(100),
    updater character varying(100),
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.tensor_microseg_policies OWNER TO postgres;

--
-- Name: tensor_microseg_resources; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_microseg_resources (
    id bigint NOT NULL,
    segment_id bigint,
    segment_name character varying(100),
    cluster character varying(100),
    namespace character varying(100),
    kind character varying(100),
    name character varying(100),
    policy character varying(100),
    network_type smallint,
    resource_tag smallint,
    status smallint,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.tensor_microseg_resources OWNER TO postgres;

--
-- Name: tensor_microseg_rules; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_microseg_rules (
    policy character varying(100),
    direction smallint,
    src_type smallint,
    src_id bigint,
    src_ip_block character varying(100),
    dst_type smallint,
    dst_id bigint,
    dst_ip_block character varying(100),
    action smallint,
    protocol smallint,
    ports character varying(100),
    comment text,
    is_seg_rule boolean,
    status smallint,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.tensor_microseg_rules OWNER TO postgres;

--
-- Name: tensor_microseg_segments; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_microseg_segments (
    id bigint NOT NULL,
    name character varying(100),
    cluster character varying(100),
    namespace character varying(100),
    policy character varying(100),
    creator character varying(100),
    updater character varying(100),
    status smallint,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.tensor_microseg_segments OWNER TO postgres;

--
-- Name: tensor_microseg_tenants; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_microseg_tenants (
    id bigint NOT NULL,
    uuid bigint NOT NULL,
    name character varying(100),
    cluster character varying(100),
    policy_namespace character varying(100),
    namespaces character varying(1024),
    users character varying(1024),
    logic_cluster bigint DEFAULT '-1'::integer,
    privilege integer,
    status smallint,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.tensor_microseg_tenants OWNER TO postgres;

--
-- Name: tensor_microseg_tenants_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_microseg_tenants_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_microseg_tenants_id_seq OWNER TO postgres;

--
-- Name: tensor_microseg_tenants_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_microseg_tenants_id_seq OWNED BY public.tensor_microseg_tenants.id;


--
-- Name: tensor_module; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_module (
    id integer NOT NULL,
    module_name_zh text,
    module_name_en text
);


ALTER TABLE public.tensor_module OWNER TO postgres;

--
-- Name: tensor_module_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_module_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_module_id_seq OWNER TO postgres;

--
-- Name: tensor_module_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_module_id_seq OWNED BY public.tensor_module.id;


--
-- Name: tensor_namespaces; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_namespaces (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    status smallint DEFAULT 0,
    name text,
    cluster_key text,
    uid text,
    owner_references jsonb,
    labels jsonb,
    alias character varying(256),
    managers jsonb,
    authority character varying(64),
    tenant_or_nsgrp smallint DEFAULT 0
);


ALTER TABLE public.tensor_namespaces OWNER TO postgres;

--
-- Name: tensor_network_flows; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_network_flows (
    uuid bigint NOT NULL,
    src_cluster character varying(100),
    src_namespace character varying(100),
    src_kind character varying(100),
    src_name character varying(100),
    dst_cluster character varying(100),
    dst_namespace character varying(100),
    dst_kind character varying(100),
    dst_name character varying(100),
    proto smallint,
    dst_port integer,
    status integer,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    src_container_name character varying(100),
    src_process character varying(100),
    dst_container_name character varying(100),
    dst_process character varying(100)
);


ALTER TABLE public.tensor_network_flows OWNER TO postgres;

--
-- Name: tensor_nodes; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_nodes (
    id bigint NOT NULL,
    cluster_key character varying(128) NOT NULL,
    host_name character varying(128) NOT NULL,
    node_ip character varying(128) NOT NULL,
    kernel_version character varying(256),
    os_info character varying(256),
    container_runtime_version character varying(256),
    kubelet_version character varying(256),
    kube_proxy_version character varying(256),
    architecture character varying(256),
    os_image character varying(256),
    volumes jsonb,
    container_images jsonb,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    status smallint
);


ALTER TABLE public.tensor_nodes OWNER TO postgres;

--
-- Name: tensor_pod_res_relations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_pod_res_relations (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    status smallint DEFAULT 0,
    pod_ip text,
    pod_uid text,
    host_ip text,
    cluster_key text,
    namespace text,
    pod_name text,
    resource_name text,
    resource_kind text,
    node_name character varying(256),
    pod_container_infos jsonb
);


ALTER TABLE public.tensor_pod_res_relations OWNER TO postgres;

--
-- Name: tensor_resources; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_resources (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    status smallint DEFAULT 0,
    name text,
    namespace text,
    cluster_key text,
    uid text,
    kind text,
    label_selector jsonb,
    owner_references jsonb,
    labels jsonb,
    pod_template jsonb,
    alias character varying(256),
    managers jsonb,
    authority character varying(64)
);


ALTER TABLE public.tensor_resources OWNER TO postgres;

--
-- Name: tensor_scan_config; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_scan_config (
    id bigint NOT NULL,
    vuln_flush_trig_enable boolean DEFAULT false,
    malicious_flush_trig_enable boolean DEFAULT false,
    library_image_config text DEFAULT ''::text,
    node_image_config text DEFAULT ''::text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at bigint DEFAULT 0
);


ALTER TABLE public.tensor_scan_config OWNER TO postgres;

--
-- Name: tensor_scan_config_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_scan_config_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_scan_config_id_seq OWNER TO postgres;

--
-- Name: tensor_scan_config_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_scan_config_id_seq OWNED BY public.tensor_scan_config.id;


--
-- Name: tensor_scan_report_sub_tasks; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_scan_report_sub_tasks (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    type smallint DEFAULT 0,
    scan_report_id bigint,
    file bytea,
    start_timestamp bigint,
    end_timestamp bigint,
    status smallint,
    failed_count smallint DEFAULT 0 NOT NULL
);


ALTER TABLE public.tensor_scan_report_sub_tasks OWNER TO postgres;

--
-- Name: COLUMN tensor_scan_report_sub_tasks.type; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_sub_tasks.type IS '任务类型,周期任务:0,一次性任务:1';


--
-- Name: COLUMN tensor_scan_report_sub_tasks.scan_report_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_sub_tasks.scan_report_id IS '报告ID,对应report_tasks表的主键';


--
-- Name: COLUMN tensor_scan_report_sub_tasks.file; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_sub_tasks.file IS '报告内容';


--
-- Name: COLUMN tensor_scan_report_sub_tasks.start_timestamp; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_sub_tasks.start_timestamp IS '开始时间';


--
-- Name: COLUMN tensor_scan_report_sub_tasks.end_timestamp; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_sub_tasks.end_timestamp IS '结束时间';


--
-- Name: COLUMN tensor_scan_report_sub_tasks.status; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_sub_tasks.status IS '任务状态，待执行:0,执行中:1,成功:2,失败:3,取消:4';


--
-- Name: COLUMN tensor_scan_report_sub_tasks.failed_count; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_sub_tasks.failed_count IS '失败的次数';


--
-- Name: tensor_scan_report_sub_tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_scan_report_sub_tasks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_scan_report_sub_tasks_id_seq OWNER TO postgres;

--
-- Name: tensor_scan_report_sub_tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_scan_report_sub_tasks_id_seq OWNED BY public.tensor_scan_report_sub_tasks.id;


--
-- Name: tensor_scan_report_tasks; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_scan_report_tasks (
    id bigint NOT NULL,
    name text,
    type smallint,
    content_type smallint,
    image_type smallint,
    comment text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at bigint DEFAULT 0,
    cycle_day smallint,
    start_timestamp bigint,
    end_timestamp bigint,
    last_timestamp bigint,
    registry_image_type smallint,
    registry_image_objects jsonb,
    node_image_objects jsonb,
    emails jsonb
);


ALTER TABLE public.tensor_scan_report_tasks OWNER TO postgres;

--
-- Name: COLUMN tensor_scan_report_tasks.name; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_tasks.name IS '报告名称,长度限制,100个字符';


--
-- Name: COLUMN tensor_scan_report_tasks.type; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_tasks.type IS '报告类型：1:周报，2:月报，3:自定义';


--
-- Name: COLUMN tensor_scan_report_tasks.content_type; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_tasks.content_type IS '报告类型:风险镜像列表:0b1,漏洞列表:0b10,病毒列表:0b100,修复建议:0b1000,多个内容求或运算';


--
-- Name: COLUMN tensor_scan_report_tasks.image_type; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_tasks.image_type IS '报告对象,仓库镜像:0b1, 节点镜像:0b10,多个求或运算';


--
-- Name: COLUMN tensor_scan_report_tasks.comment; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_tasks.comment IS '报告描述，500字符限制';


--
-- Name: COLUMN tensor_scan_report_tasks.cycle_day; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_tasks.cycle_day IS '间隔时间，可以表示周几或者每个月的第几号';


--
-- Name: COLUMN tensor_scan_report_tasks.start_timestamp; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_tasks.start_timestamp IS '自定义的开始时间';


--
-- Name: COLUMN tensor_scan_report_tasks.end_timestamp; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_tasks.end_timestamp IS '结束时间';


--
-- Name: COLUMN tensor_scan_report_tasks.last_timestamp; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_tasks.last_timestamp IS '最后一次生成时间';


--
-- Name: COLUMN tensor_scan_report_tasks.registry_image_type; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tensor_scan_report_tasks.registry_image_type IS '仓库镜像类型 1:项目 2:仓库 3:项目仓库';


--
-- Name: tensor_scan_report_tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_scan_report_tasks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_scan_report_tasks_id_seq OWNER TO postgres;

--
-- Name: tensor_scan_report_tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_scan_report_tasks_id_seq OWNED BY public.tensor_scan_report_tasks.id;


--
-- Name: tensor_scan_strategy; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_scan_strategy (
    id bigint NOT NULL,
    name text DEFAULT ''::text,
    describe text DEFAULT ''::text,
    operator text DEFAULT ''::text,
    is_default boolean DEFAULT false,
    sensitive_file text DEFAULT ''::text,
    envs text DEFAULT ''::text,
    open_license text DEFAULT ''::text,
    software text DEFAULT ''::text,
    envs_enable boolean DEFAULT false,
    software_enable boolean DEFAULT false,
    open_license_enable boolean DEFAULT false,
    sensitive_enable boolean DEFAULT false,
    vul_enable boolean DEFAULT false,
    webshell_enable boolean DEFAULT false,
    malicious_enable boolean DEFAULT false,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at bigint DEFAULT 0
);


ALTER TABLE public.tensor_scan_strategy OWNER TO postgres;

--
-- Name: tensor_scan_strategy_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_scan_strategy_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_scan_strategy_id_seq OWNER TO postgres;

--
-- Name: tensor_scan_strategy_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_scan_strategy_id_seq OWNED BY public.tensor_scan_strategy.id;


--
-- Name: tensor_scan_subtask; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_scan_subtask (
    id bigint NOT NULL,
    task_id bigint DEFAULT 0,
    image_id bigint DEFAULT 0,
    status bigint DEFAULT 0,
    result bigint DEFAULT 0,
    err_msg text DEFAULT ''::text,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    heart_beat timestamp with time zone
);


ALTER TABLE public.tensor_scan_subtask OWNER TO postgres;

--
-- Name: tensor_scan_subtask_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_scan_subtask_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_scan_subtask_id_seq OWNER TO postgres;

--
-- Name: tensor_scan_subtask_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_scan_subtask_id_seq OWNED BY public.tensor_scan_subtask.id;


--
-- Name: tensor_scan_task; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_scan_task (
    id bigint NOT NULL,
    scan_type text DEFAULT ''::text,
    scope_type bigint DEFAULT 0,
    sub_task_count bigint DEFAULT 0,
    trigger bigint DEFAULT 0,
    flow_conf text DEFAULT ''::text,
    priority bigint DEFAULT 0,
    status bigint DEFAULT 0,
    result bigint DEFAULT 0,
    msg text DEFAULT ''::text,
    comment text DEFAULT ''::text,
    operator text DEFAULT ''::text,
    policy_id bigint,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    heart_beat timestamp with time zone,
    scanner_id text
);


ALTER TABLE public.tensor_scan_task OWNER TO postgres;

--
-- Name: tensor_scan_task_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_scan_task_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_scan_task_id_seq OWNER TO postgres;

--
-- Name: tensor_scan_task_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_scan_task_id_seq OWNED BY public.tensor_scan_task.id;


--
-- Name: tensor_url; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_url (
    id integer NOT NULL,
    url_id bigint,
    url_name text
);


ALTER TABLE public.tensor_url OWNER TO postgres;

--
-- Name: tensor_url_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_url_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_url_id_seq OWNER TO postgres;

--
-- Name: tensor_url_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_url_id_seq OWNED BY public.tensor_url.id;


--
-- Name: tensor_user; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tensor_user (
    id integer NOT NULL,
    username text,
    pwd text,
    salt text,
    rule text,
    module_id text,
    checked boolean,
    create_at bigint,
    ban_status integer,
    tenant bigint DEFAULT '-1'::integer
);


ALTER TABLE public.tensor_user OWNER TO postgres;

--
-- Name: tensor_user_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tensor_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tensor_user_id_seq OWNER TO postgres;

--
-- Name: tensor_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tensor_user_id_seq OWNED BY public.tensor_user.id;


--
-- Name: trusted_images; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.trusted_images (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    digest character(71) NOT NULL,
    is_trusted smallint DEFAULT 0
);


ALTER TABLE public.trusted_images OWNER TO postgres;

--
-- Name: COLUMN trusted_images.digest; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.trusted_images.digest IS '镜像的digest';


--
-- Name: COLUMN trusted_images.is_trusted; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.trusted_images.is_trusted IS '是否为可信,0为不可信,1为可信';


--
-- Name: trusted_images_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.trusted_images_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.trusted_images_id_seq OWNER TO postgres;

--
-- Name: trusted_images_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.trusted_images_id_seq OWNED BY public.trusted_images.id;


--
-- Name: vuln_images; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vuln_images (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at bigint,
    vuln_name text,
    image_id bigint
);


ALTER TABLE public.vuln_images OWNER TO postgres;

--
-- Name: vuln_images_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.vuln_images_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.vuln_images_id_seq OWNER TO postgres;

--
-- Name: vuln_images_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.vuln_images_id_seq OWNED BY public.vuln_images.id;


--
-- Name: vulns; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vulns (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at bigint,
    name text,
    namespace text,
    description text,
    link_json jsonb,
    severity text,
    severity_int bigint,
    metadata_json jsonb,
    pkg_name text,
    pkg_version text,
    fixed_by text,
    extra_info jsonb,
    target text
);


ALTER TABLE public.vulns OWNER TO postgres;

--
-- Name: vulns_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.vulns_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.vulns_id_seq OWNER TO postgres;

--
-- Name: vulns_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.vulns_id_seq OWNED BY public.vulns.id;


--
-- Name: web_frame_scans; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.web_frame_scans (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    image_uuid bigint,
    web_frame_info jsonb
);


ALTER TABLE public.web_frame_scans OWNER TO postgres;

--
-- Name: web_frame_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.web_frame_scans_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.web_frame_scans_id_seq OWNER TO postgres;

--
-- Name: web_frame_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.web_frame_scans_id_seq OWNED BY public.web_frame_scans.id;


--
-- Name: apparmor_profiles id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.apparmor_profiles ALTER COLUMN id SET DEFAULT nextval('public.apparmor_profiles_id_seq'::regclass);


--
-- Name: association_events id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.association_events ALTER COLUMN id SET DEFAULT nextval('public.association_events_id_seq'::regclass);


--
-- Name: attck_rule_datas id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.attck_rule_datas ALTER COLUMN id SET DEFAULT nextval('public.attck_rule_datas_id_seq'::regclass);


--
-- Name: attck_rule_masks id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.attck_rule_masks ALTER COLUMN id SET DEFAULT nextval('public.attck_rule_masks_id_seq'::regclass);


--
-- Name: command_whitelist_profiles id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.command_whitelist_profiles ALTER COLUMN id SET DEFAULT nextval('public.command_whitelist_profiles_id_seq'::regclass);


--
-- Name: drift_profiles id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.drift_profiles ALTER COLUMN id SET DEFAULT nextval('public.drift_profiles_id_seq'::regclass);


--
-- Name: gc_tasks id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.gc_tasks ALTER COLUMN id SET DEFAULT nextval('public.gc_tasks_id_seq'::regclass);


--
-- Name: image_relate id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.image_relate ALTER COLUMN id SET DEFAULT nextval('public.image_relate_id_seq'::regclass);


--
-- Name: image_rsa id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.image_rsa ALTER COLUMN id SET DEFAULT nextval('public.image_rsa_id_seq'::regclass);


--
-- Name: image_whitelist id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.image_whitelist ALTER COLUMN id SET DEFAULT nextval('public.image_whitelist_id_seq'::regclass);


--
-- Name: immune_policies id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.immune_policies ALTER COLUMN id SET DEFAULT nextval('public.immune_policies_id_seq'::regclass);


--
-- Name: immune_tasks id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.immune_tasks ALTER COLUMN id SET DEFAULT nextval('public.immune_tasks_id_seq'::regclass);


--
-- Name: ldap_groups id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ldap_groups ALTER COLUMN id SET DEFAULT nextval('public.ldap_groups_id_seq'::regclass);


--
-- Name: openapi_auth_token id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.openapi_auth_token ALTER COLUMN id SET DEFAULT nextval('public.openapi_auth_token_id_seq'::regclass);


--
-- Name: palace_assoc_graph_events id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.palace_assoc_graph_events ALTER COLUMN id SET DEFAULT nextval('public.palace_assoc_graph_events_id_seq'::regclass);


--
-- Name: processingcenter_actions id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.processingcenter_actions ALTER COLUMN id SET DEFAULT nextval('public.processingcenter_actions_id_seq'::regclass);


--
-- Name: registries id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.registries ALTER COLUMN id SET DEFAULT nextval('public.registries_id_seq'::regclass);


--
-- Name: reject_policy id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reject_policy ALTER COLUMN id SET DEFAULT nextval('public.reject_policy_id_seq'::regclass);


--
-- Name: reject_record id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reject_record ALTER COLUMN id SET DEFAULT nextval('public.reject_record_id_seq'::regclass);


--
-- Name: reject_vuln id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reject_vuln ALTER COLUMN id SET DEFAULT nextval('public.reject_vuln_id_seq'::regclass);


--
-- Name: report_task_templates id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.report_task_templates ALTER COLUMN id SET DEFAULT nextval('public.report_task_templates_id_seq'::regclass);


--
-- Name: rules id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.rules ALTER COLUMN id SET DEFAULT nextval('public.rules_id_seq'::regclass);


--
-- Name: scan_bench_result id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.scan_bench_result ALTER COLUMN id SET DEFAULT nextval('public.scan_bench_result_id_seq'::regclass);


--
-- Name: scan_images id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.scan_images ALTER COLUMN id SET DEFAULT nextval('public.scan_images_id_seq'::regclass);


--
-- Name: scan_layers id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.scan_layers ALTER COLUMN id SET DEFAULT nextval('public.scan_layers_id_seq'::regclass);


--
-- Name: seccomp_profiles id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seccomp_profiles ALTER COLUMN id SET DEFAULT nextval('public.seccomp_profiles_id_seq'::regclass);


--
-- Name: security_policies id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.security_policies ALTER COLUMN id SET DEFAULT nextval('public.security_policies_id_seq'::regclass);


--
-- Name: security_policy_resources id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.security_policy_resources ALTER COLUMN id SET DEFAULT nextval('public.security_policy_resources_id_seq'::regclass);


--
-- Name: tensor_apis id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_apis ALTER COLUMN id SET DEFAULT nextval('public.tensor_apis_id_seq'::regclass);


--
-- Name: tensor_email id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_email ALTER COLUMN id SET DEFAULT nextval('public.tensor_email_id_seq'::regclass);


--
-- Name: tensor_image_list id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_image_list ALTER COLUMN id SET DEFAULT nextval('public.tensor_image_list_id_seq'::regclass);


--
-- Name: tensor_microseg_logic_clusters id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_microseg_logic_clusters ALTER COLUMN id SET DEFAULT nextval('public.tensor_microseg_logic_clusters_id_seq'::regclass);


--
-- Name: tensor_microseg_nsgrps id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_microseg_nsgrps ALTER COLUMN id SET DEFAULT nextval('public.tensor_microseg_nsgrps_id_seq'::regclass);


--
-- Name: tensor_microseg_tenants id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_microseg_tenants ALTER COLUMN id SET DEFAULT nextval('public.tensor_microseg_tenants_id_seq'::regclass);


--
-- Name: tensor_module id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_module ALTER COLUMN id SET DEFAULT nextval('public.tensor_module_id_seq'::regclass);


--
-- Name: tensor_scan_config id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_config ALTER COLUMN id SET DEFAULT nextval('public.tensor_scan_config_id_seq'::regclass);


--
-- Name: tensor_scan_report_sub_tasks id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_report_sub_tasks ALTER COLUMN id SET DEFAULT nextval('public.tensor_scan_report_sub_tasks_id_seq'::regclass);


--
-- Name: tensor_scan_report_tasks id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_report_tasks ALTER COLUMN id SET DEFAULT nextval('public.tensor_scan_report_tasks_id_seq'::regclass);


--
-- Name: tensor_scan_strategy id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_strategy ALTER COLUMN id SET DEFAULT nextval('public.tensor_scan_strategy_id_seq'::regclass);


--
-- Name: tensor_scan_subtask id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_subtask ALTER COLUMN id SET DEFAULT nextval('public.tensor_scan_subtask_id_seq'::regclass);


--
-- Name: tensor_scan_task id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_task ALTER COLUMN id SET DEFAULT nextval('public.tensor_scan_task_id_seq'::regclass);


--
-- Name: tensor_url id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_url ALTER COLUMN id SET DEFAULT nextval('public.tensor_url_id_seq'::regclass);


--
-- Name: tensor_user id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_user ALTER COLUMN id SET DEFAULT nextval('public.tensor_user_id_seq'::regclass);


--
-- Name: trusted_images id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.trusted_images ALTER COLUMN id SET DEFAULT nextval('public.trusted_images_id_seq'::regclass);


--
-- Name: vuln_images id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vuln_images ALTER COLUMN id SET DEFAULT nextval('public.vuln_images_id_seq'::regclass);


--
-- Name: vulns id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vulns ALTER COLUMN id SET DEFAULT nextval('public.vulns_id_seq'::regclass);


--
-- Name: web_frame_scans id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.web_frame_scans ALTER COLUMN id SET DEFAULT nextval('public.web_frame_scans_id_seq'::regclass);


--
-- Name: apparmor_profiles apparmor_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.apparmor_profiles
    ADD CONSTRAINT apparmor_profiles_pkey PRIMARY KEY (id);


--
-- Name: association_events association_events_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.association_events
    ADD CONSTRAINT association_events_pkey PRIMARY KEY (id);


--
-- Name: attck_rule_datas attck_rule_datas_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.attck_rule_datas
    ADD CONSTRAINT attck_rule_datas_pkey PRIMARY KEY (id);


--
-- Name: attck_rule_masks attck_rule_masks_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.attck_rule_masks
    ADD CONSTRAINT attck_rule_masks_pkey PRIMARY KEY (id);


--
-- Name: command_whitelist_profiles command_whitelist_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.command_whitelist_profiles
    ADD CONSTRAINT command_whitelist_profiles_pkey PRIMARY KEY (id);


--
-- Name: drift_profiles drift_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.drift_profiles
    ADD CONSTRAINT drift_profiles_pkey PRIMARY KEY (id);


--
-- Name: gc_tasks gc_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.gc_tasks
    ADD CONSTRAINT gc_tasks_pkey PRIMARY KEY (id);


--
-- Name: image_relate image_relate_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.image_relate
    ADD CONSTRAINT image_relate_pkey PRIMARY KEY (id);


--
-- Name: image_rsa image_rsa_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.image_rsa
    ADD CONSTRAINT image_rsa_pkey PRIMARY KEY (id);


--
-- Name: image_whitelist image_whitelist_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.image_whitelist
    ADD CONSTRAINT image_whitelist_pkey PRIMARY KEY (id);


--
-- Name: immune_policies immune_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.immune_policies
    ADD CONSTRAINT immune_policies_pkey PRIMARY KEY (id);


--
-- Name: immune_profiles immune_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.immune_profiles
    ADD CONSTRAINT immune_profiles_pkey PRIMARY KEY (uuid);


--
-- Name: immune_tasks immune_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.immune_tasks
    ADD CONSTRAINT immune_tasks_pkey PRIMARY KEY (id);


--
-- Name: kube_hunter_records kube_hunter_records_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.kube_hunter_records
    ADD CONSTRAINT kube_hunter_records_pkey PRIMARY KEY (uuid);


--
-- Name: ldap_groups ldap_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ldap_groups
    ADD CONSTRAINT ldap_groups_pkey PRIMARY KEY (id);


--
-- Name: migrations_record migrations_record_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.migrations_record
    ADD CONSTRAINT migrations_record_pkey PRIMARY KEY (version);


--
-- Name: openapi_auth_token openapi_auth_token_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.openapi_auth_token
    ADD CONSTRAINT openapi_auth_token_pkey PRIMARY KEY (id);


--
-- Name: palace_assoc_graph_events palace_assoc_graph_events_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.palace_assoc_graph_events
    ADD CONSTRAINT palace_assoc_graph_events_pkey PRIMARY KEY (id);


--
-- Name: palace_assoc_links palace_assoc_links_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.palace_assoc_links
    ADD CONSTRAINT palace_assoc_links_pkey PRIMARY KEY (uuid);


--
-- Name: palace_evt_signal_assocs palace_evt_signal_assocs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.palace_evt_signal_assocs
    ADD CONSTRAINT palace_evt_signal_assocs_pkey PRIMARY KEY (uuid);


--
-- Name: processingcenter_actions processingcenter_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.processingcenter_actions
    ADD CONSTRAINT processingcenter_actions_pkey PRIMARY KEY (id);


--
-- Name: registries registries_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.registries
    ADD CONSTRAINT registries_pkey PRIMARY KEY (id);


--
-- Name: reject_policy reject_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reject_policy
    ADD CONSTRAINT reject_policy_pkey PRIMARY KEY (id);


--
-- Name: reject_record reject_record_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reject_record
    ADD CONSTRAINT reject_record_pkey PRIMARY KEY (id);


--
-- Name: reject_vuln reject_vuln_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reject_vuln
    ADD CONSTRAINT reject_vuln_pkey PRIMARY KEY (id);


--
-- Name: report_records report_records_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.report_records
    ADD CONSTRAINT report_records_pkey PRIMARY KEY (uuid);


--
-- Name: report_task_templates report_task_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.report_task_templates
    ADD CONSTRAINT report_task_templates_pkey PRIMARY KEY (id);


--
-- Name: rules rules_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_pkey PRIMARY KEY (id);


--
-- Name: scan_bench_history scan_bench_history_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.scan_bench_history
    ADD CONSTRAINT scan_bench_history_pkey PRIMARY KEY (task_id);


--
-- Name: scan_bench_result scan_bench_result_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.scan_bench_result
    ADD CONSTRAINT scan_bench_result_pkey PRIMARY KEY (id);


--
-- Name: scan_images scan_images_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.scan_images
    ADD CONSTRAINT scan_images_pkey PRIMARY KEY (id);


--
-- Name: scan_layers scan_layers_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.scan_layers
    ADD CONSTRAINT scan_layers_pkey PRIMARY KEY (id);


--
-- Name: seccomp_profiles seccomp_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seccomp_profiles
    ADD CONSTRAINT seccomp_profiles_pkey PRIMARY KEY (id);


--
-- Name: security_policies security_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.security_policies
    ADD CONSTRAINT security_policies_pkey PRIMARY KEY (id);


--
-- Name: security_policy_resources security_policy_resources_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.security_policy_resources
    ADD CONSTRAINT security_policy_resources_pkey PRIMARY KEY (id);


--
-- Name: tensor_apis tensor_apis_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_apis
    ADD CONSTRAINT tensor_apis_pkey PRIMARY KEY (id);


--
-- Name: tensor_clusters tensor_clusters_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_clusters
    ADD CONSTRAINT tensor_clusters_pkey PRIMARY KEY (key);


--
-- Name: tensor_configs tensor_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_configs
    ADD CONSTRAINT tensor_configs_pkey PRIMARY KEY (key);


--
-- Name: tensor_containers tensor_containers_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_containers
    ADD CONSTRAINT tensor_containers_pkey PRIMARY KEY (id);


--
-- Name: tensor_email tensor_email_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_email
    ADD CONSTRAINT tensor_email_pkey PRIMARY KEY (id);


--
-- Name: tensor_image_list tensor_image_list_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_image_list
    ADD CONSTRAINT tensor_image_list_pkey PRIMARY KEY (id);


--
-- Name: tensor_microseg_logic_clusters tensor_microseg_logic_clusters_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_microseg_logic_clusters
    ADD CONSTRAINT tensor_microseg_logic_clusters_pkey PRIMARY KEY (id);


--
-- Name: tensor_microseg_nsgrps tensor_microseg_nsgrps_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_microseg_nsgrps
    ADD CONSTRAINT tensor_microseg_nsgrps_pkey PRIMARY KEY (id);


--
-- Name: tensor_microseg_policies tensor_microseg_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_microseg_policies
    ADD CONSTRAINT tensor_microseg_policies_pkey PRIMARY KEY (name);


--
-- Name: tensor_microseg_resources tensor_microseg_resources_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_microseg_resources
    ADD CONSTRAINT tensor_microseg_resources_pkey PRIMARY KEY (id);


--
-- Name: tensor_microseg_segments tensor_microseg_segments_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_microseg_segments
    ADD CONSTRAINT tensor_microseg_segments_pkey PRIMARY KEY (id);


--
-- Name: tensor_microseg_tenants tensor_microseg_tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_microseg_tenants
    ADD CONSTRAINT tensor_microseg_tenants_pkey PRIMARY KEY (id);


--
-- Name: tensor_module tensor_module_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_module
    ADD CONSTRAINT tensor_module_pkey PRIMARY KEY (id);


--
-- Name: tensor_namespaces tensor_namespaces_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_namespaces
    ADD CONSTRAINT tensor_namespaces_pkey PRIMARY KEY (id);


--
-- Name: tensor_network_flows tensor_network_flows_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_network_flows
    ADD CONSTRAINT tensor_network_flows_pkey PRIMARY KEY (uuid);


--
-- Name: tensor_nodes tensor_nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_nodes
    ADD CONSTRAINT tensor_nodes_pkey PRIMARY KEY (id);


--
-- Name: tensor_pod_res_relations tensor_pod_res_relations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_pod_res_relations
    ADD CONSTRAINT tensor_pod_res_relations_pkey PRIMARY KEY (id);


--
-- Name: tensor_resources tensor_resources_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_resources
    ADD CONSTRAINT tensor_resources_pkey PRIMARY KEY (id);


--
-- Name: tensor_scan_config tensor_scan_config_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_config
    ADD CONSTRAINT tensor_scan_config_pkey PRIMARY KEY (id);


--
-- Name: tensor_scan_report_sub_tasks tensor_scan_report_sub_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_report_sub_tasks
    ADD CONSTRAINT tensor_scan_report_sub_tasks_pkey PRIMARY KEY (id);


--
-- Name: tensor_scan_report_tasks tensor_scan_report_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_report_tasks
    ADD CONSTRAINT tensor_scan_report_tasks_pkey PRIMARY KEY (id);


--
-- Name: tensor_scan_strategy tensor_scan_strategy_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_strategy
    ADD CONSTRAINT tensor_scan_strategy_pkey PRIMARY KEY (id);


--
-- Name: tensor_scan_subtask tensor_scan_subtask_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_subtask
    ADD CONSTRAINT tensor_scan_subtask_pkey PRIMARY KEY (id);


--
-- Name: tensor_scan_task tensor_scan_task_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_task
    ADD CONSTRAINT tensor_scan_task_pkey PRIMARY KEY (id);


--
-- Name: tensor_url tensor_url_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_url
    ADD CONSTRAINT tensor_url_pkey PRIMARY KEY (id);


--
-- Name: tensor_user tensor_user_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_user
    ADD CONSTRAINT tensor_user_pkey PRIMARY KEY (id);


--
-- Name: trusted_images trusted_images_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.trusted_images
    ADD CONSTRAINT trusted_images_pkey PRIMARY KEY (id);


--
-- Name: vuln_images vuln_images_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vuln_images
    ADD CONSTRAINT vuln_images_pkey PRIMARY KEY (id);


--
-- Name: vulns vulns_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vulns
    ADD CONSTRAINT vulns_pkey PRIMARY KEY (id);


--
-- Name: web_frame_scans web_frame_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.web_frame_scans
    ADD CONSTRAINT web_frame_scans_pkey PRIMARY KEY (id);


--
-- Name: association_events_created_at_key; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX association_events_created_at_key ON public.association_events USING btree (created_at);


--
-- Name: association_events_rule_category_at_key_1; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX association_events_rule_category_at_key_1 ON public.association_events USING btree (rule_category, updated_at, id);


--
-- Name: association_events_rule_category_at_key_2; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX association_events_rule_category_at_key_2 ON public.association_events USING btree (rule_category, severity, id);


--
-- Name: association_events_severity_key; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX association_events_severity_key ON public.association_events USING btree (severity, id);


--
-- Name: association_events_updated_at_key; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX association_events_updated_at_key ON public.association_events USING btree (updated_at, id);


--
-- Name: attck_rule_data_created_at_key; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX attck_rule_data_created_at_key ON public.attck_rule_datas USING btree (created_at);


--
-- Name: attck_rule_masks_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX attck_rule_masks_name ON public.attck_rule_masks USING btree (name);


--
-- Name: digest_library; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX digest_library ON public.image_relate USING btree (digest, library, container_id);


--
-- Name: email_username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX email_username ON public.tensor_email USING btree (username);


--
-- Name: end_time_index; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX end_time_index ON public.tensor_scan_report_sub_tasks USING btree (end_timestamp);


--
-- Name: gc_tasks_hash_key; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX gc_tasks_hash_key ON public.gc_tasks USING btree (hash);


--
-- Name: hash_code; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX hash_code ON public.tensor_email USING btree (hash_code);


--
-- Name: idx_apis_updated; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_apis_updated ON public.tensor_apis USING btree (updated_at);


--
-- Name: idx_aprr_res; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_aprr_res ON public.tensor_pod_res_relations USING btree (cluster_key, namespace, resource_kind, resource_name);


--
-- Name: idx_center_assoc_links_search; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_center_assoc_links_search ON public.palace_assoc_links USING btree (aggr_evt_id);


--
-- Name: idx_cron_task; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cron_task ON public.cron_scan_task USING btree (cluster_id, check_type);


--
-- Name: idx_flow_dname; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_flow_dname ON public.tensor_network_flows USING btree (dst_name);


--
-- Name: idx_flow_sname; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_flow_sname ON public.tensor_network_flows USING btree (src_name);


--
-- Name: idx_gc_tasks_category; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_gc_tasks_category ON public.gc_tasks USING btree (category);


--
-- Name: idx_image; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_image ON public.tensor_scan_subtask USING btree (image_id);


--
-- Name: idx_image_digest; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_image_digest ON public.tensor_image_list USING btree (digest);


--
-- Name: idx_image_rsa_deleted_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_image_rsa_deleted_at ON public.image_rsa USING btree (deleted_at);


--
-- Name: idx_image_uuid; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_image_uuid ON public.tensor_image_list USING btree (image_uuid);


--
-- Name: idx_immune_policies_cls; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_immune_policies_cls ON public.immune_policies USING btree (cluster_key, updated_at);


--
-- Name: idx_immune_policies_kind_query; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_immune_policies_kind_query ON public.immune_policies USING btree (kind, updated_at);


--
-- Name: idx_immune_policies_res_query; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_immune_policies_res_query ON public.immune_policies USING btree (resource_uuid);


--
-- Name: idx_immune_profiles_query; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_immune_profiles_query ON public.immune_profiles USING btree (policy_id, container_name);


--
-- Name: idx_immune_tasks_query; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_immune_tasks_query ON public.immune_tasks USING btree (resource_uuid);


--
-- Name: idx_logiccluster_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_logiccluster_name ON public.tensor_microseg_logic_clusters USING btree (name, cluster);


--
-- Name: idx_nsgrps_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_nsgrps_name ON public.tensor_microseg_nsgrps USING btree (name, cluster);


--
-- Name: idx_nsgrps_uuid; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_nsgrps_uuid ON public.tensor_microseg_nsgrps USING btree (uuid);


--
-- Name: idx_palace_signal_assocs_query; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_palace_signal_assocs_query ON public.palace_evt_signal_assocs USING btree (aggr_evt_id, aggr_key);


--
-- Name: idx_processingcenter_actions_record_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_processingcenter_actions_record_id ON public.processingcenter_actions USING btree (record_id);


--
-- Name: idx_prv_dig; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_prv_dig ON public.image_rsa USING btree (private_key_digest);


--
-- Name: idx_reject_record; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_reject_record ON public.reject_record USING btree (full_repo_name, tag);


--
-- Name: idx_reject_record_reject_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_reject_record_reject_at ON public.reject_record USING btree (reject_at);


--
-- Name: idx_report_records_template_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_report_records_template_id ON public.report_records USING btree (template_id);


--
-- Name: idx_report_task_templates_generate_timestamp; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_report_task_templates_generate_timestamp ON public.report_task_templates USING btree (latest_generate_timestamp);


--
-- Name: idx_res_sid; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_res_sid ON public.tensor_microseg_resources USING btree (segment_id);


--
-- Name: idx_res_sname; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_res_sname ON public.tensor_microseg_resources USING btree (segment_name);


--
-- Name: idx_rule_policy; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_rule_policy ON public.tensor_microseg_rules USING btree (policy);


--
-- Name: idx_scan_image; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_scan_image ON public.scan_images USING btree (image_id);


--
-- Name: idx_seg_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_seg_name ON public.tensor_microseg_segments USING btree (name);


--
-- Name: idx_task; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_task ON public.tensor_scan_subtask USING btree (task_id);


--
-- Name: idx_task_export; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_task_export ON public.scan_export_task USING btree (task_id);


--
-- Name: idx_task_history; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_task_history ON public.scan_bench_history USING btree (task_id);


--
-- Name: idx_task_node; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_task_node ON public.scan_node_record USING btree (task_id, node_name);


--
-- Name: idx_task_policy; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_task_policy ON public.scan_policy_detail USING btree (policy_id, check_type);


--
-- Name: idx_task_result; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_task_result ON public.scan_bench_result USING btree (task_id);


--
-- Name: idx_tc_image; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tc_image ON public.tensor_containers USING btree (image_uuid);


--
-- Name: idx_tc_list_q; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tc_list_q ON public.tensor_containers USING btree (cluster_key, namespace, resource_kind, resource_name);


--
-- Name: idx_tcontainer_app_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tcontainer_app_type ON public.tensor_containers USING btree (app_type);


--
-- Name: idx_tenants_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tenants_name ON public.tensor_microseg_tenants USING btree (name, cluster);


--
-- Name: idx_tenants_uuid; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tenants_uuid ON public.tensor_microseg_tenants USING btree (uuid);


--
-- Name: idx_tensor_pod_res_relations_node_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tensor_pod_res_relations_node_name ON public.tensor_pod_res_relations USING btree (cluster_key, node_name);


--
-- Name: idx_tensor_scan_report_sub_tasks_deleted_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tensor_scan_report_sub_tasks_deleted_at ON public.tensor_scan_report_sub_tasks USING btree (deleted_at);


--
-- Name: idx_tn_list_q; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tn_list_q ON public.tensor_namespaces USING btree (cluster_key);


--
-- Name: idx_tr_list_q; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tr_list_q ON public.tensor_resources USING btree (cluster_key, namespace, kind);


--
-- Name: idx_trusted_images_deleted_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_trusted_images_deleted_at ON public.trusted_images USING btree (deleted_at);


--
-- Name: idx_web_frame_scans_deleted_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_web_frame_scans_deleted_at ON public.web_frame_scans USING btree (deleted_at);


--
-- Name: kube_hunter_records_cluster; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX kube_hunter_records_cluster ON public.kube_hunter_records USING btree (cluster);


--
-- Name: library_image; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX library_image ON public.image_whitelist USING btree (library, full_repo_name, tag);


--
-- Name: library_image_tag; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX library_image_tag ON public.image_whitelist USING btree (library, full_repo_name, tag);


--
-- Name: name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX name ON public.security_policies USING btree (name);


--
-- Name: open_api_auth_token_token; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX open_api_auth_token_token ON public.openapi_auth_token USING btree (token);


--
-- Name: open_api_auth_token_username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX open_api_auth_token_username ON public.openapi_auth_token USING btree (username);


--
-- Name: report_name_unique_index; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX report_name_unique_index ON public.tensor_scan_report_tasks USING btree (name, deleted_at);


--
-- Name: rules_key; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX rules_key ON public.rules USING btree (name, category, module);


--
-- Name: scan_report_sub_tasks_uqx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX scan_report_sub_tasks_uqx ON public.tensor_scan_report_sub_tasks USING btree (scan_report_id, end_timestamp);


--
-- Name: uniq_apis_api; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_apis_api ON public.tensor_apis USING btree (path, resource, namespace, kind, cluster, method);


--
-- Name: uniq_idx_digest_library; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_digest_library ON public.image_relate USING btree (digest, library, container_id);


--
-- Name: uniq_idx_image_relate; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_image_relate ON public.image_relate USING btree (digest, library, container_id);


--
-- Name: uniq_idx_imagelist; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_imagelist ON public.tensor_image_list USING btree (full_repo_name, tags, registry_id, from_type);


--
-- Name: uniq_idx_library_image_tag; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_library_image_tag ON public.image_whitelist USING btree (library, full_repo_name, tag);


--
-- Name: uniq_idx_registry_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_registry_name ON public.registries USING btree (name, deleted_at);


--
-- Name: uniq_idx_reject_vuln; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_reject_vuln ON public.reject_vuln USING btree (reject_policy_id, library, name);


--
-- Name: uniq_idx_scan_layer; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_scan_layer ON public.scan_layers USING btree (image_id, layer_digest);


--
-- Name: uniq_idx_scan_strategy_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_scan_strategy_name ON public.tensor_scan_strategy USING btree (name);


--
-- Name: uniq_idx_vnlu_image; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_vnlu_image ON public.vuln_images USING btree (vuln_name, image_id);


--
-- Name: uniq_idx_vuln; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_vuln ON public.vulns USING btree (name, pkg_name, pkg_version);


--
-- Name: uniq_idx_white_image; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_idx_white_image ON public.image_whitelist USING btree (full_repo_name, tag, library);


--
-- Name: uniq_ldap_group_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_ldap_group_name ON public.ldap_groups USING btree (name);


--
-- Name: uniq_report_task_templates_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_report_task_templates_name ON public.report_task_templates USING btree (name);


--
-- Name: uniq_webframescan_uuid; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uniq_webframescan_uuid ON public.web_frame_scans USING btree (image_uuid);


--
-- Name: uqi_digest; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uqi_digest ON public.trusted_images USING btree (digest);


--
-- Name: uqi_rsa_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uqi_rsa_id ON public.image_rsa USING btree (rsa_id);


--
-- Name: username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX username ON public.tensor_user USING btree (username);


--
-- Name: apparmor_profile_data fk_apparmor_profiles_apparmor_profile_data; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.apparmor_profile_data
    ADD CONSTRAINT fk_apparmor_profiles_apparmor_profile_data FOREIGN KEY (apparmor_profile_id) REFERENCES public.apparmor_profiles(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: command_whitelist_profile_data fk_command_whitelist_profiles_command_whitelist_profile_data; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.command_whitelist_profile_data
    ADD CONSTRAINT fk_command_whitelist_profiles_command_whitelist_profile_data FOREIGN KEY (command_whitelist_profile_id) REFERENCES public.command_whitelist_profiles(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: seccomp_profile_data fk_seccomp_profiles_seccomp_profile_data; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seccomp_profile_data
    ADD CONSTRAINT fk_seccomp_profiles_seccomp_profile_data FOREIGN KEY (seccomp_profile_id) REFERENCES public.seccomp_profiles(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: apparmor_profiles fk_security_policies_apparmor_profile; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.apparmor_profiles
    ADD CONSTRAINT fk_security_policies_apparmor_profile FOREIGN KEY (security_policy_id) REFERENCES public.security_policies(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: command_whitelist_profiles fk_security_policies_command_whitelist_profile; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.command_whitelist_profiles
    ADD CONSTRAINT fk_security_policies_command_whitelist_profile FOREIGN KEY (security_policy_id) REFERENCES public.security_policies(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: drift_profiles fk_security_policies_drift_profile; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.drift_profiles
    ADD CONSTRAINT fk_security_policies_drift_profile FOREIGN KEY (security_policy_id) REFERENCES public.security_policies(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: security_policy_resources fk_security_policies_resources; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.security_policy_resources
    ADD CONSTRAINT fk_security_policies_resources FOREIGN KEY (security_policy_id) REFERENCES public.security_policies(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: seccomp_profiles fk_security_policies_seccomp_profile; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seccomp_profiles
    ADD CONSTRAINT fk_security_policies_seccomp_profile FOREIGN KEY (security_policy_id) REFERENCES public.security_policies(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: tensor_scan_report_sub_tasks fk_tensor_scan_report_sub_tasks_tensor_scan_report_tasks; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tensor_scan_report_sub_tasks
    ADD CONSTRAINT fk_tensor_scan_report_sub_tasks_tensor_scan_report_tasks FOREIGN KEY (scan_report_id) REFERENCES public.tensor_scan_report_tasks(id);


DELETE FROM public.event_notify_settings;

INSERT INTO public.event_notify_settings (email_notification, emails, threshold_severity) VALUES (FALSE, '{}', 0);

--
-- PostgreSQL database dump complete
--

`
)
