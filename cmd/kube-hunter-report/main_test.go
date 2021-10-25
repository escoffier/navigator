package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/PuerkitoBio/goquery"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func TestContent(t *testing.T) {
	jsonStr := `{"nodes": [{"type": "Node/Master", "location": "10.39.0.1"}], 
				"services": [{"service": "API Server", "location": "10.39.0.1:443"}], 
				"vulnerabilities": [{"location": "Local to Pod (kube-hunter-1-jsn9h)", "vid": "None", "category": "Lateral Movement // ARP poisoning and IP spoofing", "severity": "medium", "vulnerability": "CAP_NET_RAW Enabled", "description": "CAP_NET_RAW is enabled by default for pods.\n    If an attacker manages to compromise a pod,\n    they could potentially take advantage of this capability to perform network\n    attacks on other pods running on the same node", "evidence": "", "avd_reference": "https://avd.aquasec.com/kube-hunter/none/", "hunter": "Pod Capabilities Hunter"}, {"location": "Local to Pod (kube-hunter-1-jsn9h)", "vid": "KHV050", "category": "Credential Access // Access container service account", "severity": "low", "vulnerability": "Read access to pod's service account token", "description": "Accessing the pod service account token gives an attacker the option to use the server API", "evidence": "eyJhbGciOiJSUzI1NiIsImtpZCI6IlNkRGtDcTdZN2RScC05WWhIaU1FNEhkWmZqbndvVWFiaU5YbU53YTlJTUkifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJ0ZW5zb3JzZWMtdGVzdC1jbiIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJkZWZhdWx0LXRva2VuLXducmJuIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImRlZmF1bHQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiJjYzExODQxYy01MDk4LTQyMDUtYWZjMi02Nzg4YzIyODRiNzUiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6dGVuc29yc2VjLXRlc3QtY246ZGVmYXVsdCJ9.Yo-7YfvmUVzLgYd0j3qfp-cdM2Ptcf_icU-RwEeYmKVY2Dyc4D5vS6AUTSYSkspdEtG-KaxDWBWKJmKLcfJP7klDf5oR5OoJ9GCGK3Piu0sX5Oy-pxxrTn2mBsYY9d70EszMhxCXxM31zYZcIcTmam58_9xEGG706cI8-ciwpY29Qad8R_I1Ktl9fsvpv-GrOUbIxt5QXelSS1dgcoFnlJ3DkUZoOPsYiqEQJJHuGfOL_whOae-Nm1SEToBEf5pXN5zoqnsx9qAMciEJqKgBJlUR_GjVi_YQHX1EFRfcIICEw4Z76f3BJitHX9GX-yzRnpGcNUYV2HOvdNWJkRVNWA", "avd_reference": "https://avd.aquasec.com/kube-hunter/khv050/", "hunter": "Access Secrets"}, {"location": "Local to Pod (kube-hunter-1-jsn9h)", "vid": "None", "category": "Credential Access // Access container service account", "severity": "low", "vulnerability": "Access to pod's secrets", "description": "Accessing the pod's secrets within a compromised pod might disclose valuable data to a potential attacker", "evidence": "['/var/run/secrets/kubernetes.io/serviceaccount/ca.crt', '/var/run/secrets/kubernetes.io/serviceaccount/token', '/var/run/secrets/kubernetes.io/serviceaccount/namespace', '/var/run/secrets/kubernetes.io/serviceaccount/..2021_10_13_09_05_49.074524111/ca.crt', '/var/run/secrets/kubernetes.io/serviceaccount/..2021_10_13_09_05_49.074524111/token', '/var/run/secrets/kubernetes.io/serviceaccount/..2021_10_13_09_05_49.074524111/namespace']", "avd_reference": "https://avd.aquasec.com/kube-hunter/none/", "hunter": "Access Secrets"}, {"location": "10.39.0.1:443", "vid": "KHV002", "category": "Initial Access // Exposed sensitive interfaces", "severity": "high", "vulnerability": "K8s Version Disclosure", "description": "The kubernetes version could be obtained from the /version endpoint", "evidence": "v1.19.11", "avd_reference": "https://avd.aquasec.com/kube-hunter/khv002/", "hunter": "Api Version Hunter"}, {"location": "10.39.0.1:443", "vid": "KHV005", "category": "Discovery // Access the K8S API Server", "severity": "medium", "vulnerability": "Access to API using service account token", "description": "The API Server port is accessible.\n    Depending on your RBAC settings this could expose access to or control of your cluster.", "evidence": "b'{\"kind\":\"APIVersions\",\"versions\":[\"v1\"],\"serverAddressByClientCIDRs\":[{\"clientCIDR\":\"0.0.0.0/0\",\"serverAddress\":\"172.21.0.3:6443\"}]}\\n'", "avd_reference": "https://avd.aquasec.com/kube-hunter/khv005/", "hunter": "API Server Hunter"}]}`
	var content model.RawKubeHunterContent
	err := json.Unmarshal([]byte(jsonStr), &content)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(content)
}

func TestUnquote(t *testing.T) {
	str := `"{\"nodes\": [{\"type\": \"Node/Master\", \"location\": \"10.39.0.1\"}], \"services\": [{\"service\": \"API Server\", \"location\": \"10.39.0.1:443\"}], \"vulnerabilities\": [{\"location\": \"Local to Pod (tensorsec-kube-hunter-report-89l8d)\", \"vid\": \"KHV050\", \"category\": \"Credential Access // Access container service account\", \"severity\": \"low\", \"vulnerability\": \"Read access to pod's service account token\", \"description\": \"Accessing the pod service account token gives an attacker the option to use the server API\", \"evidence\": \"eyJhbGciOiJSUzI1NiIsImtpZCI6IlNkRGtDcTdZN2RScC05WWhIaU1FNEhkWmZqbndvVWFiaU5YbU53YTlJTUkifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJ0ZW5zb3JzZWMtdGVzdC1jbiIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJkZWZhdWx0LXRva2VuLXducmJuIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImRlZmF1bHQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiJjYzExODQxYy01MDk4LTQyMDUtYWZjMi02Nzg4YzIyODRiNzUiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6dGVuc29yc2VjLXRlc3QtY246ZGVmYXVsdCJ9.Yo-7YfvmUVzLgYd0j3qfp-cdM2Ptcf_icU-RwEeYmKVY2Dyc4D5vS6AUTSYSkspdEtG-KaxDWBWKJmKLcfJP7klDf5oR5OoJ9GCGK3Piu0sX5Oy-pxxrTn2mBsYY9d70EszMhxCXxM31zYZcIcTmam58_9xEGG706cI8-ciwpY29Qad8R_I1Ktl9fsvpv-GrOUbIxt5QXelSS1dgcoFnlJ3DkUZoOPsYiqEQJJHuGfOL_whOae-Nm1SEToBEf5pXN5zoqnsx9qAMciEJqKgBJlUR_GjVi_YQHX1EFRfcIICEw4Z76f3BJitHX9GX-yzRnpGcNUYV2HOvdNWJkRVNWA\", \"avd_reference\": \"https://avd.aquasec.com/kube-hunter/khv050/\", \"hunter\": \"Access Secrets\"}, {\"location\": \"Local to Pod (tensorsec-kube-hunter-report-89l8d)\", \"vid\": \"None\", \"category\": \"Credential Access // Access container service account\", \"severity\": \"low\", \"vulnerability\": \"Access to pod's secrets\", \"description\": \"Accessing the pod's secrets within a compromised pod might disclose valuable data to a potential attacker\", \"evidence\": \"['/var/run/secrets/kubernetes.io/serviceaccount/ca.crt', '/var/run/secrets/kubernetes.io/serviceaccount/token', '/var/run/secrets/kubernetes.io/serviceaccount/namespace', '/var/run/secrets/kubernetes.io/serviceaccount/..2021_10_14_10_43_41.381470086/ca.crt', '/var/run/secrets/kubernetes.io/serviceaccount/..2021_10_14_10_43_41.381470086/token', '/var/run/secrets/kubernetes.io/serviceaccount/..2021_10_14_10_43_41.381470086/namespace']\", \"avd_reference\": \"https://avd.aquasec.com/kube-hunter/none/\", \"hunter\": \"Access Secrets\"}, {\"location\": \"Local to Pod (tensorsec-kube-hunter-report-89l8d)\", \"vid\": \"None\", \"category\": \"Lateral Movement // ARP poisoning and IP spoofing\", \"severity\": \"medium\", \"vulnerability\": \"CAP_NET_RAW Enabled\", \"description\": \"CAP_NET_RAW is enabled by default for pods.\\n    If an attacker manages to compromise a pod,\\n    they could potentially take advantage of this capability to perform network\\n    attacks on other pods running on the same node\", \"evidence\": \"\", \"avd_reference\": \"https://avd.aquasec.com/kube-hunter/none/\", \"hunter\": \"Pod Capabilities Hunter\"}, {\"location\": \"10.39.0.1:443\", \"vid\": \"KHV002\", \"category\": \"Initial Access // Exposed sensitive interfaces\", \"severity\": \"high\", \"vulnerability\": \"K8s Version Disclosure\", \"description\": \"The kubernetes version could be obtained from the /version endpoint\", \"evidence\": \"v1.19.11\", \"avd_reference\": \"https://avd.aquasec.com/kube-hunter/khv002/\", \"hunter\": \"Api Version Hunter\"}, {\"location\": \"10.39.0.1:443\", \"vid\": \"KHV005\", \"category\": \"Discovery // Access the K8S API Server\", \"severity\": \"medium\", \"vulnerability\": \"Access to API using service account token\", \"description\": \"The API Server port is accessible.\\n    Depending on your RBAC settings this could expose access to or control of your cluster.\", \"evidence\": \"b'{\\\"kind\\\":\\\"APIVersions\\\",\\\"versions\\\":[\\\"v1\\\"],\\\"serverAddressByClientCIDRs\\\":[{\\\"clientCIDR\\\":\\\"0.0.0.0/0\\\",\\\"serverAddress\\\":\\\"172.21.0.3:6443\\\"}]}\\\\n'\", \"avd_reference\": \"https://avd.aquasec.com/kube-hunter/khv005/\", \"hunter\": \"API Server Hunter\"}]}"`
	parsed, err := strconv.Unquote(str)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(parsed)
}

func TestGetVulnerabilityDetail(t *testing.T) {
	var infos []*detail
	for i := 1; i < 60; i++ {
		info, err := loadVulnerabilityDetail(i)
		if err == ErrNotFound {
			continue
		}
		infos = append(infos, info)
	}

	jsonBytes, err := json.MarshalIndent(infos, "", "	")
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("khv_detail.json", jsonBytes, 0644)
	if err != nil {
		t.Fatal(err)
	}
}

type detail struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

var (
	ErrNotFound = errors.New("not found")
)

func loadVulnerabilityDetail(id int) (*detail, error) {
	response, err := http.Get(fmt.Sprintf("https://avd.aquasec.com/kube-hunter/khv%03d/", id))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == 404 {
		return nil, ErrNotFound
	}

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected id:%d, statusCode:%d", id, response.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		return nil, fmt.Errorf("NewDocumentFromReader fail")
	}

	var result = &detail{Name: fmt.Sprintf("KHV%03d", id)}
	doc.Find("p").Each(func(i int, s *goquery.Selection) {
		// For each item found, get the title
		if i == 1 {
			result.Description = s.Text()
		} else if i == 2 {
			result.Remediation = s.Text()
		}
	})

	if result.Description == "" || result.Remediation == "" {
		return nil, fmt.Errorf("unexpected info, id:%d, description:%s, remediation:%s",
			id, result.Description, result.Remediation)
	}

	return result, nil
}

func TestGenerateURL(t *testing.T) {
	url, err := generateURL("uuid")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(url)
}
