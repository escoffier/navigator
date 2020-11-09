package scapper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/host"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/kube"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scapper"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type severity string

const (
	severityLow  severity = "Low"
	severityHigh severity = "High"
)

var (
	// This map is hardcoded for now, as discussed with HH.
	// In the future, we may let user adjust alerts.
	// Values come from:
	// https://tensorsecurity.feishu.cn/sheets/shtcnDRmdGD2nWT89XiLGOfVcBc
	benchAlerts = map[model.ComplianceCheckType]map[string]severity{
		// Kube bench supports multiple CIS versions.
		// Kube bench decides which version to use based on detected Kubernetes version.
		// Rule IDs change between CIS versions.
		// Therefore, for now we disable automatic detection. We force usage of CIS-1.3 version.
		// Rule IDs here are compatible with CIS-1.3.
		// If we want to support more, newer CIS versions, we need to adjust this mapping.
		model.ComplianceCheckTargetTypeKube: {
			"1.1.10": severityHigh, // Ensure that the admission control plugin AlwaysAdmit is not set
			"1.1.11": severityHigh, // Ensure that the admission control plugin AlwaysPullImages is set
			"1.1.12": severityHigh, // Ensure that the admission control plugin DenyEscalatingExec is set
			"1.1.13": severityHigh, // Ensure that the admission control plugin SecurityContextDeny is set
			"1.1.14": severityHigh, // Ensure that the admission control plugin NamespaceLifecycle is set
			"1.1.2":  severityHigh, // Ensure that the --basic-auth-file argument is not set
			"1.1.20": severityHigh, // Ensure that the --token-auth-file parameter is not set
			"1.1.24": severityHigh, // Ensure that the admission control plugin PodSecurityPolicy is set
			"1.1.25": severityHigh, // Ensure that the --service-account-key-file argument is set as appropriate
			"1.1.26": severityHigh, // Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate
			"1.1.28": severityHigh, // Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
			"1.1.29": severityHigh, // Ensure that the --client-ca-file argument is set as appropriate
			"1.1.3":  severityHigh, // Ensure that the --insecure-allow-any-token argument is not set
			"1.1.30": severityLow,  // Ensure that the API Server only makes use of Strong Cryptographic Ciphers
			"1.1.4":  severityHigh, // Ensure that the --kubelet-https argument is set to true
			"1.1.5":  severityHigh, // Ensure that the --insecure-bind-address argument is not set
			"1.1.6":  severityHigh, // Ensure that the --insecure-port argument is set to 0
			"1.1.7":  severityHigh, // Ensure that the --secure-port argument is not set to 0
			"1.3.3":  severityHigh, // Ensure that the --use-service-account-credentials argument is set to true
			"1.3.4":  severityHigh, // Ensure that the --service-account-private-key-file argument is set as appropriate
			"1.3.5":  severityHigh, // Ensure that the --root-ca-file argument is set as appropriate
			"1.4.1":  severityLow,  // Ensure that the API server pod specification file permissions are set to 644 or more restrictive
			"1.4.10": severityLow,  // Ensure that the Container Network Interface file ownership is set to root:root
			"1.4.11": severityLow,  // Ensure that the etcd data directory permissions are set to 700 or more restrictive
			"1.4.12": severityLow,  // Ensure that the etcd data directory ownership is set to etcd:etcd
			"1.4.13": severityLow,  // Ensure that the admin.conf file permissions are set to 644 or more restrictive
			"1.4.14": severityLow,  // Ensure that the admin.conf file ownership is set to root:root
			"1.4.15": severityLow,  // Ensure that the scheduler.conf file permissions are set to 644 or more restrictive
			"1.4.16": severityLow,  // Ensure that the scheduler.conf file ownership is set to root:root
			"1.4.17": severityLow,  // Ensure that the controller-manager.conf file permissions are set to 644 or more restrictive
			"1.4.18": severityLow,  // Ensure that the controller-manager.conf file ownership is set to root:root
			"1.4.2":  severityLow,  // Ensure that the API server pod specification file ownership is set to root:root
			"1.4.3":  severityLow,  // Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive
			"1.4.4":  severityLow,  // Ensure that the controller manager pod specification file ownership is set to root:root
			"1.4.5":  severityLow,  // Ensure that the scheduler pod specification file permissions are set to 644 or more restrictive
			"1.4.6":  severityLow,  // Ensure that the scheduler pod specification file ownership is set to root:root
			"1.4.7":  severityLow,  // Ensure that the etcd pod specification file permissions are set to 644 or more restrictive
			"1.4.8":  severityLow,  // Ensure that the etcd pod specification file ownership is set to root:root
			"1.4.9":  severityLow,  // Ensure that the Container Network Interface file permissions are set to 644 or more restrictive
			"1.6.1":  severityLow,  // Ensure that the cluster-admin role is only used where required
			"1.6.2":  severityLow,  // Create administrative boundaries between resources using namespaces
			"1.6.3":  severityLow,  // Create network segmentation using Network Policies
			"1.6.4":  severityLow,  // Ensure that the seccomp profile is set to docker/default in your pod definitions
			"1.6.5":  severityLow,  // Apply Security Context to Your Pods and Containers
			"1.6.6":  severityLow,  // Configure Image Provenance using ImagePolicyWebhook admission controller
			"1.6.7":  severityLow,  // Configure Network policies as appropriate
			"1.6.8":  severityLow,  // Place compensating controls in the form of PSP and RBAC for privileged containers usage
			"1.7.1":  severityHigh, // Do not admit privileged containers
			"1.7.2":  severityLow,  // Do not admit containers wishing to share the host process ID namespace
			"1.7.3":  severityLow,  // Do not admit containers wishing to share the host IPC namespace
			"1.7.4":  severityLow,  // Do not admit containers wishing to share the host network namespace
			"1.7.5":  severityHigh, // Do not admit containers with allowPrivilegeEscalation
			"1.7.6":  severityHigh, // Do not admit root containers
			"1.7.7":  severityHigh, // Do not admit containers with dangerous capabilities
			"2.2.1":  severityLow,  // Ensure that the kubelet.conf file permissions are set to 644 or more restrictive
			"2.2.10": severityLow,  // Ensure that the kubelet configuration file has permissions set to 644 or more restrictive
			"2.2.2":  severityLow,  // Ensure that the kubelet.conf file ownership is set to root:root
			"2.2.3":  severityLow,  // Ensure that the kubelet service file permissions are set to 644 or more restrictive
			"2.2.4":  severityLow,  // Ensure that the kubelet service file ownership is set to root:root
			"2.2.5":  severityLow,  // Ensure that the proxy kubeconfig file permissions are set to 644 or more restrictive
			"2.2.6":  severityLow,  // Ensure that the proxy kubeconfig file ownership is set to root:root
			"2.2.7":  severityLow,  // Ensure that the certificate authorities file permissions are set to 644 or more restrictive
			"2.2.8":  severityLow,  // Ensure that the client certificate authorities file ownership is set to root:root
			"2.2.9":  severityLow,  // Ensure that the kubelet configuration file ownership is set to root:root
		},
		model.ComplianceCheckTargetTypeDocker: {
			"1.2.10": severityLow,  // Ensure auditing is configured for Docker files and directories - /etc/docker/daemon.json
			"1.2.11": severityLow,  // Ensure auditing is configured for Docker files and directories - /usr/bin/containerd
			"1.2.12": severityLow,  // Ensure auditing is configured for Docker files and directories - /usr/sbin/runc
			"1.2.2":  severityHigh, // Ensure only trusted users are allowed to control Docker daemon
			"1.2.3":  severityLow,  // Ensure auditing is configured for the Docker daemon
			"1.2.4":  severityLow,  // Ensure auditing is configured for Docker files and directories - /var/lib/docker
			"1.2.5":  severityLow,  // Ensure auditing is configured for Docker files and directories - /etc/docker
			"1.2.6":  severityLow,  // Ensure auditing is configured for Docker files and directories - docker.service
			"1.2.7":  severityLow,  // Ensure auditing is configured for Docker files and directories - docker.socket
			"1.2.8":  severityLow,  // Ensure auditing is configured for Docker files and directories - /etc/default/docker
			"1.2.9":  severityLow,  // Ensure auditing is configured for Docker files and directories - /etc/sysconfig/docker
			"2.1":    severityLow,  // Ensure network traffic is restricted between containers on the default bridge
			"2.14":   severityLow,  // Ensure Userland Proxy is Disabled
			"2.15":   severityLow,  // Ensure that a daemon-wide custom seccomp profile is applied if appropriate
			"2.17":   severityLow,  // Ensure containers are restricted from acquiring new privileges
			"2.6":    severityLow,  // Ensure TLS authentication for Docker daemon is configured
			"3.1":    severityLow,  // Ensure that the docker.service file ownership is set to root:root
			"3.10":   severityLow,  // Ensure that TLS CA certificate file permissions are set to 444 or more restrictively
			"3.11":   severityLow,  // Ensure that Docker server certificate file ownership is set to root:root
			"3.12":   severityLow,  // Ensure that the Docker server certificate file permissions are set to 444 or more restrictively
			"3.13":   severityLow,  // Ensure that the Docker server certificate key file ownership is set to root:root
			"3.14":   severityLow,  // Ensure that the Docker server certificate key file permissions are set to 400
			"3.15":   severityLow,  // Ensure that the Docker socket file ownership is set to root:docker
			"3.16":   severityLow,  // Ensure that the Docker socket file permissions are set to 660 or more restrictively
			"3.17":   severityLow,  // Ensure that the daemon.json file ownership is set to root:root
			"3.18":   severityLow,  // Ensure that daemon.json file permissions are set to 644 or more restrictive
			"3.19":   severityLow,  // Ensure that the /etc/default/docker file ownership is set to root:root
			"3.2":    severityLow,  // Ensure that docker.service file permissions are appropriately set
			"3.20":   severityLow,  // Ensure that the /etc/sysconfig/docker file ownership is set to root:root
			"3.21":   severityLow,  // Ensure that the /etc/sysconfig/docker file permissions are set to 644 or more restrictively
			"3.22":   severityLow,  // Ensure that the /etc/default/docker file permissions are set to 644 or more restrictively
			"3.3":    severityLow,  // Ensure that docker.socket file ownership is set to root:root
			"3.4":    severityLow,  // Ensure that docker.socket file permissions are set to 644 or more restrictive
			"3.5":    severityLow,  // Ensure that the /etc/docker directory ownership is set to root:root
			"3.6":    severityLow,  // Ensure that /etc/docker directory permissions are set to 755 or more restrictively
			"3.7":    severityLow,  // Ensure that registry certificate file ownership is set to root:root
			"3.8":    severityLow,  // Ensure that registry certificate file permissions are set to 444 or more restrictively
			"3.9":    severityHigh, // Ensure that TLS CA certificate file ownership is set to root:root
			"4.10":   severityHigh, // Ensure secrets are not stored in Dockerfiles
			"4.5":    severityLow,  // Ensure Content trust for Docker is Enabled
			"4.8":    severityLow,  // Ensure setuid and setgid permissions are removed
			"4.9":    severityLow,  // Ensure that COPY is used instead of ADD in Dockerfiles
			"5.1":    severityLow,  // Ensure that, if applicable, an AppArmor Profile is enabled
			"5.12":   severityHigh, // Ensure that the container's root filesystem is mounted as read only
			"5.2":    severityLow,  // Ensure that, if applicable, SELinux security options are set
			"5.21":   severityLow,  // Ensurethe default seccomp profile is not Disabled
			"5.23":   severityLow,  // Ensure that docker exec commands are not used with the user=root option
			"5.25":   severityLow,  // Ensure that the container is restricted from acquiring additional privileges
			"5.29":   severityLow,  // Ensure that Docker's default bridge docker0 is not used
			"5.3":    severityLow,  // Ensure that Linux kernel capabilities are restricted within containers
			"5.31":   severityLow,  // Ensure that the Docker socket is not mounted inside any containers
			"5.4":    severityLow,  // Ensure that privileged containers are not used
			"5.5":    severityLow,  // Ensure sensitive host system directories are not mounted on containers
			"5.6":    severityHigh, // Ensure sshd is not run within containers
			"5.7":    severityHigh, // Ensure privileged ports are not mapped within containers
			"7.4":    severityLow,  // Ensure that all Docker swarm overlay networks are encrypted
		},
		model.ComplianceCheckTargetTypeHost: {
			"xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write":           severityLow,  // Ensure that Root's Path Does Not Include World or Group-Writable Directories
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_chmod":         severityLow,  // Record Events that Modify the System's Discretionary Access Controls - chmod
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_chown":         severityLow,  // Record Events that Modify the System's Discretionary Access Controls - chown
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fchmod":        severityLow,  // Record Events that Modify the System's Discretionary Access Controls - fchmod
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fchmodat":      severityLow,  // Record Events that Modify the System's Discretionary Access Controls - fchmodat
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fchown":        severityLow,  // Record Events that Modify the System's Discretionary Access Controls - fchown
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fchownat":      severityLow,  // Record Events that Modify the System's Discretionary Access Controls - fchownat
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fremovexattr":  severityLow,  // Record Events that Modify the System's Discretionary Access Controls - fremovexattr
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_fsetxattr":     severityLow,  // Record Events that Modify the System's Discretionary Access Controls - fsetxattr
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_lchown":        severityLow,  // Record Events that Modify the System's Discretionary Access Controls - lchown
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_lremovexattr":  severityLow,  // Record Events that Modify the System's Discretionary Access Controls - lremovexattr
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_lsetxattr":     severityLow,  // Record Events that Modify the System's Discretionary Access Controls - lsetxattr
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_removexattr":   severityLow,  // Record Events that Modify the System's Discretionary Access Controls - removexattr
			"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_setxattr":      severityLow,  // Record Events that Modify the System's Discretionary Access Controls - setxattr
			"xccdf_org.ssgproject.content_rule_audit_rules_kernel_module_loading":          severityHigh, // Ensure auditd Collects Information on Kernel Module Loading and Unloading
			"xccdf_org.ssgproject.content_rule_audit_rules_mac_modification":               severityHigh, // Record Events that Modify the System's Mandatory Access Controls
			"xccdf_org.ssgproject.content_rule_audit_rules_privileged_commands":            severityHigh, // Ensure auditd Collects Information on the Use of Privileged Commands
			"xccdf_org.ssgproject.content_rule_audit_rules_sysadmin_actions":               severityLow,  // Ensure auditd Collects System Administrator Actions
			"xccdf_org.ssgproject.content_rule_audit_rules_time_adjtimex":                  severityLow,  // Record attempts to alter time through adjtimex
			"xccdf_org.ssgproject.content_rule_audit_rules_time_clock_settime":             severityLow,  // Record Attempts to Alter Time Through clock_settime
			"xccdf_org.ssgproject.content_rule_audit_rules_time_settimeofday":              severityLow,  // Record attempts to alter time through settimeofday
			"xccdf_org.ssgproject.content_rule_audit_rules_time_stime":                     severityLow,  // Record Attempts to Alter Time Through stime
			"xccdf_org.ssgproject.content_rule_audit_rules_time_watch_localtime":           severityLow,  // Record Attempts to Alter the localtime File
			"xccdf_org.ssgproject.content_rule_audit_rules_unsuccessful_file_modification": severityLow,  // Ensure auditd Collects Unauthorized Access Attempts to Files (unsuccessful)
			"xccdf_org.ssgproject.content_rule_no_empty_passwords":                         severityHigh, // Prevent Login to Accounts With Empty Password
			"xccdf_org.ssgproject.content_rule_partition_for_var_log_audit":                severityLow,  // Ensure /var/log/audit Located On Separate Partition
			"xccdf_org.ssgproject.content_rule_security_patches_up_to_date":                severityHigh, // Ensure Software Patches Installed
			"xccdf_org.ssgproject.content_rule_service_rsyslog_enabled":                    severityLow,  // Enable rsyslog Service
		},
	}
)

func (s *Scapper) appendComplianceAlert(alertsToReport map[string]model.Alert, check *scapper.Check, policyID, description, nodeName string, sev severity) {
	if _, ok := alertsToReport[policyID]; !ok {
		alertsToReport[policyID] = model.Alert{
			ID:        primitive.NewObjectIDFromTimestamp(time.Now()),
			AlertKind: model.AlertKindComplianceCheck,
			Timestamp: time.Now(),
			Severity:  string(sev),
			ComplianceCheckAlert: &model.ComplianceCheckAlert{
				AffectedNodes: &[]string{},
				ClusterID:     check.ClusterID,
				CheckID:       check.CheckUUID.String(),
				CheckType:     string(check.CheckType),
				PolicyID:      policyID,
				Message:       util.RemoveScoredNotScoredFrom(description),
			},
		}
	}

	*alertsToReport[policyID].ComplianceCheckAlert.AffectedNodes =
		append(*alertsToReport[policyID].ComplianceCheckAlert.AffectedNodes, nodeName)

}

func (s *Scapper) generateAlerts(ctx context.Context, check *scapper.Check) error {

	logging.GetLogger().Info().
		Str("checkId", check.CheckUUID.String()).
		Str("check", fmt.Sprintf("%+v", check)).
		Msg("Generating alerts")

	jobEntries, err := s.GetJobEntriesForCheck(ctx, check.ClusterID, check.CheckType,
		check.CheckUUID.String(), "", model.ComplianceCheckStatusCompleted)
	if err != nil {
		return err
	}

	alertsToReport := make(map[string]model.Alert)

	for _, jobEntry := range jobEntries {
		jsonbody, err := json.Marshal(jobEntry.Report)
		if err != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed to marshal %T into job report: %w", jobEntry.Report, err))
		}

		switch check.CheckType {
		case model.ComplianceCheckTargetTypeKube:
			var reports map[string]kube.KubeReportResult
			err = json.Unmarshal(jsonbody, &reports)
			if err != nil {
				return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed to unmarshal into %T: %w", reports, err))
			}

			for _, report := range reports {
				for _, section := range report.Tests {
					for _, result := range section.Results {
						if severity, ok := benchAlerts[model.ComplianceCheckTargetTypeKube][result.TestNumber]; ok && result.Status == "FAIL" {
							s.appendComplianceAlert(alertsToReport, check, result.TestNumber, result.TestDescription, jobEntry.NodeName, severity)
						}
					}
				}
			}

		case model.ComplianceCheckTargetTypeDocker:
			var report docker.DockerReportResult
			err = json.Unmarshal(jsonbody, &report)
			if err != nil {
				return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed to unmarshal into %T: %w", report, err))
			}
			for _, section := range report.Tests {
				for _, result := range section.Results {
					if severity, ok := benchAlerts[model.ComplianceCheckTargetTypeDocker][result.ID]; ok && result.Result == "WARN" {
						s.appendComplianceAlert(alertsToReport, check, result.ID, result.Description, jobEntry.NodeName, severity)
					}
				}
			}

		case model.ComplianceCheckTargetTypeHost:
			var report host.HostReportResult
			err = json.Unmarshal(jsonbody, &report)
			if err != nil {
				return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed to unmarshal into %T: %w", report, err))
			}
			for _, result := range report.Results {
				if severity, ok := benchAlerts[model.ComplianceCheckTargetTypeDocker][result.RuleID]; ok && result.Result == "fail" {
					s.appendComplianceAlert(alertsToReport, check, result.RuleID, result.Title, jobEntry.NodeName, severity)
				}
			}

		default:
			return NewAnError(http.StatusInternalServerError, fmt.Errorf("Unexpected checkType %s", check.CheckType))
		}
	}

	numAlertsRaised := 0
	defer func() {
		logging.GetLogger().Info().
			Int("numAlertsToBeRaised", len(alertsToReport)).
			Int("numAlertsRaised", numAlertsRaised).
			Str("checkId", check.CheckUUID.String()).
			Msg("Alerts raised")
	}()

	for _, complianceAlert := range alertsToReport {
		_, err = s.MongoDB.Collection(model.AlertCollection).InsertOne(ctx, complianceAlert)
		if err != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed to insert alert %+v: %w", complianceAlert, err))
		}
		numAlertsRaised++
	}

	return nil
}
