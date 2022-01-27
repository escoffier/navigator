package scapper

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
)

type severity string

var (
	// This map is hardcoded for now, as discussed with HH.
	// In the future, we may let user adjust alerts.
	// Values come from:
	// https://tensorsecurity.feishu.cn/sheets/shtcnDRmdGD2nWT89XiLGOfVcBc
	// nolint:structcheck,unused,deadcode
	benchAlerts = map[model.ComplianceCheckType]map[string]severity{
		// Kube bench supports multiple CIS versions.
		// Kube bench decides which version to use based on detected Kubernetes version.
		// Rule IDs change between CIS versions.
		// Therefore, for now we disable automatic detection. We force usage of CIS-1.3 version.
		// Rule IDs here are compatible with CIS-1.3.
		// If we want to support more, newer CIS versions, we need to adjust this mapping.
		model.ComplianceCheckTargetTypeKube: {
			"1.1.10": redclair.SeverityHigh, // Ensure that the admission control plugin AlwaysAdmit is not set
			"1.1.11": redclair.SeverityHigh, // Ensure that the admission control plugin AlwaysPullImages is set
			"1.1.12": redclair.SeverityHigh, // Ensure that the admission control plugin DenyEscalatingExec is set
			"1.1.13": redclair.SeverityHigh, // Ensure that the admission control plugin SecurityContextDeny is set
			"1.1.14": redclair.SeverityHigh, // Ensure that the admission control plugin NamespaceLifecycle is set
			"1.1.2":  redclair.SeverityHigh, // Ensure that the --basic-auth-file argument is not set
			"1.1.20": redclair.SeverityHigh, // Ensure that the --token-auth-file parameter is not set
			"1.1.24": redclair.SeverityHigh, // Ensure that the admission control plugin PodSecurityPolicy is set
			"1.1.25": redclair.SeverityHigh, // Ensure that the --service-account-key-file argument is set as appropriate
			"1.1.26": redclair.SeverityHigh, // Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate
			"1.1.28": redclair.SeverityHigh, // Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
			"1.1.29": redclair.SeverityHigh, // Ensure that the --client-ca-file argument is set as appropriate
			"1.1.3":  redclair.SeverityHigh, // Ensure that the --insecure-allow-any-token argument is not set
			"1.1.30": redclair.SeverityLow,  // Ensure that the API Server only makes use of Strong Cryptographic Ciphers
			"1.1.4":  redclair.SeverityHigh, // Ensure that the --kubelet-https argument is set to true
			"1.1.5":  redclair.SeverityHigh, // Ensure that the --insecure-bind-address argument is not set
			"1.1.6":  redclair.SeverityHigh, // Ensure that the --insecure-port argument is set to 0
			"1.1.7":  redclair.SeverityHigh, // Ensure that the --secure-port argument is not set to 0
			"1.3.3":  redclair.SeverityHigh, // Ensure that the --use-service-account-credentials argument is set to true
			"1.3.4":  redclair.SeverityHigh, // Ensure that the --service-account-private-key-file argument is set as appropriate
			"1.3.5":  redclair.SeverityHigh, // Ensure that the --root-ca-file argument is set as appropriate
			"1.4.1":  redclair.SeverityLow,  // Ensure that the API server pod specification file permissions are set to 644 or more restrictive
			"1.4.10": redclair.SeverityLow,  // Ensure that the Container Network Interface file ownership is set to root:root
			"1.4.11": redclair.SeverityLow,  // Ensure that the etcd data directory permissions are set to 700 or more restrictive
			"1.4.12": redclair.SeverityLow,  // Ensure that the etcd data directory ownership is set to etcd:etcd
			"1.4.13": redclair.SeverityLow,  // Ensure that the admin.conf file permissions are set to 644 or more restrictive
			"1.4.14": redclair.SeverityLow,  // Ensure that the admin.conf file ownership is set to root:root
			"1.4.15": redclair.SeverityLow,  // Ensure that the scheduler.conf file permissions are set to 644 or more restrictive
			"1.4.16": redclair.SeverityLow,  // Ensure that the scheduler.conf file ownership is set to root:root
			"1.4.17": redclair.SeverityLow,  // Ensure that the controller-manager.conf file permissions are set to 644 or more restrictive
			"1.4.18": redclair.SeverityLow,  // Ensure that the controller-manager.conf file ownership is set to root:root
			"1.4.2":  redclair.SeverityLow,  // Ensure that the API server pod specification file ownership is set to root:root
			"1.4.3":  redclair.SeverityLow,  // Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive
			"1.4.4":  redclair.SeverityLow,  // Ensure that the controller manager pod specification file ownership is set to root:root
			"1.4.5":  redclair.SeverityLow,  // Ensure that the scheduler pod specification file permissions are set to 644 or more restrictive
			"1.4.6":  redclair.SeverityLow,  // Ensure that the scheduler pod specification file ownership is set to root:root
			"1.4.7":  redclair.SeverityLow,  // Ensure that the etcd pod specification file permissions are set to 644 or more restrictive
			"1.4.8":  redclair.SeverityLow,  // Ensure that the etcd pod specification file ownership is set to root:root
			"1.4.9":  redclair.SeverityLow,  // Ensure that the Container Network Interface file permissions are set to 644 or more restrictive
			"1.6.1":  redclair.SeverityLow,  // Ensure that the cluster-admin role is only used where required
			"1.6.2":  redclair.SeverityLow,  // Create administrative boundaries between resources using namespaces
			"1.6.3":  redclair.SeverityLow,  // Create network segmentation using Network Policies
			"1.6.4":  redclair.SeverityLow,  // Ensure that the seccomp profile is set to docker/default in your pod definitions
			"1.6.5":  redclair.SeverityLow,  // Apply Security Context to Your Pods and Containers
			"1.6.6":  redclair.SeverityLow,  // Configure Image Provenance using ImagePolicyWebhook admission controller
			"1.6.7":  redclair.SeverityLow,  // Configure Network policies as appropriate
			"1.6.8":  redclair.SeverityLow,  // Place compensating controls in the form of PSP and RBAC for privileged containers usage
			"1.7.1":  redclair.SeverityHigh, // Do not admit privileged containers
			"1.7.2":  redclair.SeverityLow,  // Do not admit containers wishing to share the host process ID namespace
			"1.7.3":  redclair.SeverityLow,  // Do not admit containers wishing to share the host IPC namespace
			"1.7.4":  redclair.SeverityLow,  // Do not admit containers wishing to share the host network namespace
			"1.7.5":  redclair.SeverityHigh, // Do not admit containers with allowPrivilegeEscalation
			"1.7.6":  redclair.SeverityHigh, // Do not admit root containers
			"1.7.7":  redclair.SeverityHigh, // Do not admit containers with dangerous capabilities
			"2.2.1":  redclair.SeverityLow,  // Ensure that the kubelet.conf file permissions are set to 644 or more restrictive
			"2.2.10": redclair.SeverityLow,  // Ensure that the kubelet configuration file has permissions set to 644 or more restrictive
			"2.2.2":  redclair.SeverityLow,  // Ensure that the kubelet.conf file ownership is set to root:root
			"2.2.3":  redclair.SeverityLow,  // Ensure that the kubelet service file permissions are set to 644 or more restrictive
			"2.2.4":  redclair.SeverityLow,  // Ensure that the kubelet service file ownership is set to root:root
			"2.2.5":  redclair.SeverityLow,  // Ensure that the proxy kubeconfig file permissions are set to 644 or more restrictive
			"2.2.6":  redclair.SeverityLow,  // Ensure that the proxy kubeconfig file ownership is set to root:root
			"2.2.7":  redclair.SeverityLow,  // Ensure that the certificate authorities file permissions are set to 644 or more restrictive
			"2.2.8":  redclair.SeverityLow,  // Ensure that the client certificate authorities file ownership is set to root:root
			"2.2.9":  redclair.SeverityLow,  // Ensure that the kubelet configuration file ownership is set to root:root
		},
		model.ComplianceCheckTargetTypeDocker: {
			"1.2.10": redclair.SeverityLow,  // Ensure auditing is configured for Docker files and directories - /etc/docker/daemon.json
			"1.2.11": redclair.SeverityLow,  // Ensure auditing is configured for Docker files and directories - /usr/bin/containerd
			"1.2.12": redclair.SeverityLow,  // Ensure auditing is configured for Docker files and directories - /usr/sbin/runc
			"1.2.2":  redclair.SeverityHigh, // Ensure only trusted users are allowed to control Docker daemon
			"1.2.3":  redclair.SeverityLow,  // Ensure auditing is configured for the Docker daemon
			"1.2.4":  redclair.SeverityLow,  // Ensure auditing is configured for Docker files and directories - /var/lib/docker
			"1.2.5":  redclair.SeverityLow,  // Ensure auditing is configured for Docker files and directories - /etc/docker
			"1.2.6":  redclair.SeverityLow,  // Ensure auditing is configured for Docker files and directories - docker.service
			"1.2.7":  redclair.SeverityLow,  // Ensure auditing is configured for Docker files and directories - docker.socket
			"1.2.8":  redclair.SeverityLow,  // Ensure auditing is configured for Docker files and directories - /etc/default/docker
			"1.2.9":  redclair.SeverityLow,  // Ensure auditing is configured for Docker files and directories - /etc/sysconfig/docker
			"2.1":    redclair.SeverityLow,  // Ensure network traffic is restricted between containers on the default bridge
			"2.14":   redclair.SeverityLow,  // Ensure Userland Proxy is Disabled
			"2.15":   redclair.SeverityLow,  // Ensure that a daemon-wide custom seccomp profile is applied if appropriate
			"2.17":   redclair.SeverityLow,  // Ensure containers are restricted from acquiring new privileges
			"2.6":    redclair.SeverityLow,  // Ensure TLS authentication for Docker daemon is configured
			"3.1":    redclair.SeverityLow,  // Ensure that the docker.service file ownership is set to root:root
			"3.10":   redclair.SeverityLow,  // Ensure that TLS CA certificate file permissions are set to 444 or more restrictively
			"3.11":   redclair.SeverityLow,  // Ensure that Docker server certificate file ownership is set to root:root
			"3.12":   redclair.SeverityLow,  // Ensure that the Docker server certificate file permissions are set to 444 or more restrictively
			"3.13":   redclair.SeverityLow,  // Ensure that the Docker server certificate key file ownership is set to root:root
			"3.14":   redclair.SeverityLow,  // Ensure that the Docker server certificate key file permissions are set to 400
			"3.15":   redclair.SeverityLow,  // Ensure that the Docker socket file ownership is set to root:docker
			"3.16":   redclair.SeverityLow,  // Ensure that the Docker socket file permissions are set to 660 or more restrictively
			"3.17":   redclair.SeverityLow,  // Ensure that the daemon.json file ownership is set to root:root
			"3.18":   redclair.SeverityLow,  // Ensure that daemon.json file permissions are set to 644 or more restrictive
			"3.19":   redclair.SeverityLow,  // Ensure that the /etc/default/docker file ownership is set to root:root
			"3.2":    redclair.SeverityLow,  // Ensure that docker.service file permissions are appropriately set
			"3.20":   redclair.SeverityLow,  // Ensure that the /etc/sysconfig/docker file ownership is set to root:root
			"3.21":   redclair.SeverityLow,  // Ensure that the /etc/sysconfig/docker file permissions are set to 644 or more restrictively
			"3.22":   redclair.SeverityLow,  // Ensure that the /etc/default/docker file permissions are set to 644 or more restrictively
			"3.3":    redclair.SeverityLow,  // Ensure that docker.socket file ownership is set to root:root
			"3.4":    redclair.SeverityLow,  // Ensure that docker.socket file permissions are set to 644 or more restrictive
			"3.5":    redclair.SeverityLow,  // Ensure that the /etc/docker directory ownership is set to root:root
			"3.6":    redclair.SeverityLow,  // Ensure that /etc/docker directory permissions are set to 755 or more restrictively
			"3.7":    redclair.SeverityLow,  // Ensure that registry certificate file ownership is set to root:root
			"3.8":    redclair.SeverityLow,  // Ensure that registry certificate file permissions are set to 444 or more restrictively
			"3.9":    redclair.SeverityHigh, // Ensure that TLS CA certificate file ownership is set to root:root
			"4.10":   redclair.SeverityHigh, // Ensure secrets are not stored in Dockerfiles
			"4.5":    redclair.SeverityLow,  // Ensure Content trust for Docker is Enabled
			"4.8":    redclair.SeverityLow,  // Ensure setuid and setgid permissions are removed
			"4.9":    redclair.SeverityLow,  // Ensure that COPY is used instead of ADD in Dockerfiles
			"5.1":    redclair.SeverityLow,  // Ensure that, if applicable, an AppArmor Profile is enabled
			"5.12":   redclair.SeverityHigh, // Ensure that the container's root filesystem is mounted as read only
			"5.2":    redclair.SeverityLow,  // Ensure that, if applicable, SELinux security options are set
			"5.21":   redclair.SeverityLow,  // Ensurethe default seccomp profile is not Disabled
			"5.23":   redclair.SeverityLow,  // Ensure that docker exec commands are not used with the user=root option
			"5.25":   redclair.SeverityLow,  // Ensure that the container is restricted from acquiring additional privileges
			"5.29":   redclair.SeverityLow,  // Ensure that Docker's default bridge docker0 is not used
			"5.3":    redclair.SeverityLow,  // Ensure that Linux kernel capabilities are restricted within containers
			"5.31":   redclair.SeverityLow,  // Ensure that the Docker socket is not mounted inside any containers
			"5.4":    redclair.SeverityLow,  // Ensure that privileged containers are not used
			"5.5":    redclair.SeverityLow,  // Ensure sensitive host system directories are not mounted on containers
			"5.6":    redclair.SeverityHigh, // Ensure sshd is not run within containers
			"5.7":    redclair.SeverityHigh, // Ensure privileged ports are not mapped within containers
			"7.4":    redclair.SeverityLow,  // Ensure that all Docker swarm overlay networks are encrypted
		},
		model.ComplianceCheckTargetTypeHost: {
			"xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write":           redclair.SeverityLow,  // Ensure that Root's Path Does Not Include World or Group-Writable Directories
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_chmod":         redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - chmod
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_chown":         redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - chown
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fchmod":        redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - fchmod
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fchmodat":      redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - fchmodat
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fchown":        redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - fchown
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fchownat":      redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - fchownat
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fremovexattr":  redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - fremovexattr
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fsetxattr":     redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - fsetxattr
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_lchown":        redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - lchown
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_lremovexattr":  redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - lremovexattr
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_lsetxattr":     redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - lsetxattr
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_removexattr":   redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - removexattr
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_setxattr":      redclair.SeverityLow,  // Record Events that Modify the System's Discretionary Access Controls - setxattr
			"xccdf_org.ssgproject.content_rule_audit_rules_kernel_module_loading":          redclair.SeverityHigh, // Ensure auditd Collects Information on Kernel Module Loading and Unloading
			"xccdf_org.ssgproject.content_rule_audit_rules_mac_modification":               redclair.SeverityHigh, // Record Events that Modify the System's Mandatory Access Controls
			"xccdf_org.ssgproject.content_rule_audit_rules_privileged_commands":            redclair.SeverityHigh, // Ensure auditd Collects Information on the Use of Privileged Commands
			"xccdf_org.ssgproject.content_rule_audit_rules_sysadmin_actions":               redclair.SeverityLow,  // Ensure auditd Collects System Administrator Actions
			"xccdf_org.ssgproject.content_rule_audit_rules_time_adjtimex":                  redclair.SeverityLow,  // Record attempts to alter time through adjtimex
			"xccdf_org.ssgproject.content_rule_audit_rules_time_clock_settime":             redclair.SeverityLow,  // Record Attempts to Alter Time Through clock_settime
			"xccdf_org.ssgproject.content_rule_audit_rules_time_settimeofday":              redclair.SeverityLow,  // Record attempts to alter time through settimeofday
			"xccdf_org.ssgproject.content_rule_audit_rules_time_stime":                     redclair.SeverityLow,  // Record Attempts to Alter Time Through stime
			"xccdf_org.ssgproject.content_rule_audit_rules_time_watch_localtime":           redclair.SeverityLow,  // Record Attempts to Alter the localtime File
			"xccdf_org.ssgproject.content_rule_audit_rules_unsuccessful_file_modification": redclair.SeverityLow,  // Ensure auditd Collects Unauthorized Access Attempts to Files (unsuccessful)
			"xccdf_org.ssgproject.content_rule_no_empty_passwords":                         redclair.SeverityHigh, // Prevent Login to Accounts With Empty Password
			"xccdf_org.ssgproject.content_rule_partition_for_var_log_audit":                redclair.SeverityLow,  // Ensure /var/log/audit Located On Separate Partition
			"xccdf_org.ssgproject.content_rule_security_patches_up_to_date":                redclair.SeverityHigh, // Ensure Software Patches Installed
			"xccdf_org.ssgproject.content_rule_service_rsyslog_enabled":                    redclair.SeverityLow,  // Enable rsyslog Service
		},
	}
)
