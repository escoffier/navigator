package kubemonitor

// NOTICE: The reason we store the rules yaml in memory is that: We don't want these rules to store in config files that it may be leaked to people we don't want.
const rulesDatastring = `######################### REGION - Risky permissions combinations #########################

# The order is important !

######################### REGION - CRITICAL Roles #########################

# Risk: Viewing specific secrets
# Verb: get
# Resources: secrets
# Example: kubectl get secrets <secret_name>

- kind: Role
  metadata:
    namespace: default
    name: risky-get-secrets
    priority: CRITICAL
    description: 
      risk: "Viewing specific secrets"
      riskCN: "有权限获取任意特定的secrets"
      verb: get
      resources: secrets
      example: "kubectl get secrets <secret_name>"
  rules:
  - apiGroups: ["*"]
    resources: ["secrets"]
    verbs: ["get"]
  

# Risk: Viewing all secrets
# Verb: list
# Resources: secrets
# Example: kubectl get secrets -o yaml

- kind: Role
  metadata:
    namespace: default
    name: risky-list-secrets
    priority: CRITICAL
    description: 
      risk: "Viewing all secrets"
      riskCN: "有权限浏览全部secrets"
      verb: list
      resources: secrets
      example: "kubectl get secrets -o yaml"
  rules:
  - apiGroups: ["*"]
    resources: ["secrets"]
    verbs: ["list"]

# Risk: Impersonate privileged groups (like 'system:masters')
# Verb: list
# Resources: secrets
# Example: kubectl get secrets -o yaml
- kind: Role
  metadata:
    namespace: default
    name: risky-impersonate-groups
    priority: CRITICAL
    description: 
      risk: "Impersonate privileged groups (like 'system:masters')"
      riskCN: "有权限伪装成特权组（比如'system:masters'）"
      verb: list
      resources: secrets
      example: "kubectl get secrets -o yaml"
  rules:
  - apiGroups: ["*"]
    resources: ["groups"]
    verbs: ["impersonate"]

######################### REGION - Any Any Roles #########################

- kind: Role
  metadata:
    namespace: default
    name: risky-any-verb
    priority: CRITICAL
    description: 
      risk: "Too wide privileges to all apiGroups/resources/verbs"
      riskCN: "对于api分组/资源/动作权限过宽"
  rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]

######################### END REGION - Any Any Roles #########################

######################### REGION - Any verb Roles #########################

- kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-secrets
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to secrets"
      riskCN: "授权对secrets做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["secrets"]
    verbs: ["*"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-pods
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to pods"
      riskCN: "授权对pods做任何动作" 
  rules:
  - apiGroups: ["*"]
    resources: ["pods"]
    verbs: ["*"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-deployments
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to deployments"
      riskCN: "授权对deployments做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["deployments"]
    verbs: ["*"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-daemonsets
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to daemonsets"
      riskCN: "授权对daemonsets做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["daemonsets"]
    verbs: ["*"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-statefulsets
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to statefulsets"
      riskCN: "授权对statefulsets做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["statefulsets"]
    verbs: ["*"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-replicationcontrollers
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to replicationControllers"
      riskCN: "授权对replicationControllers做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["replicationcontrollers"]
    verbs: ["*"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-replicasets
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to replicasetionControllers"
      riskCN: "授权对replicationControllers做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["replicasets"]
    verbs: ["*"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-cronjobs
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to cronjobs"
      riskCN: "授权对cronjobs做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["cronjobs"]
    verbs: ["*"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-jobs
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to jobs"
      riskCN: "授权对jobs做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["jobs"]
    verbs: ["*"]

  - kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-roles
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to roles"
      riskCN: "授权对roles做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["roles"]
    verbs: ["*"]

  - kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-clusterroles
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to clusterroles"
      riskCN: "授权对clusterroles做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["clusterroles"]
    verbs: ["*"]

  - kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-rolebindings
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to rolebindings"
      riskCN: "授权对rolebindings做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["rolebindings"]
    verbs: ["*"]

  - kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-clusterrolebindings
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to clusterrolebindings"
      riskCN: "授权对clusterrolebindings做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["clusterrolebindings"]
    verbs: ["*"]

  - kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-users
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to users"
      riskCN: "授权对users做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["users"]
    verbs: ["*"]

  - kind: Role
  metadata:
    namespace: default
    name: risky-any-verb-groups
    priority: CRITICAL
    description:
      risk: "authenticate any verbs to groups"
      riskCN: "授权对groups做任何动作"
  rules:
  - apiGroups: ["*"]
    resources: ["groups"]
    verbs: ["*"]

######################### END REGION - Any verb Roles #########################


######################### REGION - Any resource Roles #########################
- kind: Role
  metadata:
    namespace: default
    name: risky-any-resource-delete
    priority: CRITICAL
    description:
      risk: "authenticate delete to any resources"
      riskCN: "授权删除任意资源"
  rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["delete"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-resource-delete
    priority: CRITICAL
    description:
      risk: "authenticate deletecollection to any resources"
      riskCN: "授权删除任意资源集合"
  rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["deletecollection"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-resource-create
    priority: CRITICAL
    description:
      risk: "authenticate create to any resources"
      riskCN: "授权创建任意资源"
  rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["create"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-resource-list
    priority: CRITICAL
    description:
      risk: "authenticate list to any resources"
      riskCN: "授权罗列任意资源"
  rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["list"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-resource-get
    priority: CRITICAL
    description:
      risk: "authenticate get to any resources"
      riskCN: "授权获取任意资源"
  rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get"]

- kind: Role
  metadata:
    namespace: default
    name: risky-any-resource-impersonate
    priority: CRITICAL
    description:
      risk: "authenticate impersonate to any resources"
      riskCN: "授权伪装任意资源"
  rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["impersonate"]

######################### END REGION - Any resource Roles #########################


######################### END REGION - CRITICAL Roles #########################

######################### REGION - HIGH Roles #########################

# Risk: Allowing to create a malicious pod
# Verb: create
# Resources: deployments

- kind: Role
  metadata:
    namespace: default
    name: risky-create-deployments
    priority: MEDIUM
    description:
      risk: "Allowing to create a malicious pod"
      riskCN: "授权创建Deployments，引入可疑的pod"
      verb: "create"
      resources: "deployments"
  rules:
  - apiGroups: ["*"]
    resources: ["deployments"]
    verbs: ["create"]

# Risk: Allowing to update a malicious pod
# Verb: update
# Resources: deployments

- kind: Role
  metadata:
    namespace: default
    name: risky-update-deployments
    priority: MEDIUM
    description:
      risk: "Allowing to update a malicious pod"
      riskCN: "授权更新Deployments，引入可疑的pod"
      verb: "update"
      resources: "deployments"
  rules:
  - apiGroups: ["*"]
    resources: ["deployments"]
    verbs: ["update"]

# Risk: Allowing to create a malicious pod
# Verb: create
# Resources: daemonsets

- kind: Role
  metadata:
    namespace: default
    name: risky-create-daemonsets
    priority: MEDIUM
    description:
      risk: "Allowing to create a malicious pod"
      riskCN: "授权创建daemonsets，引入可疑的pod"
      verb: "create"
      resources: "daemonsets"
  rules:
  - apiGroups: ["*"]
    resources: ["daemonsets"]
    verbs: ["create"]

# Risk: Allowing to update a malicious pod
# Verb: update
# Resources: daemonsets

- kind: Role
  metadata:
    namespace: default
    name: risky-update-daemonsets
    priority: MEDIUM
    description:
      risk: "Allowing to update a malicious pod"
      riskCN: "授权更新daemonsets，引入可疑的pod"
      verb: "create"
      resources: "daemonsets"
  rules:
  - apiGroups: ["*"]
    resources: ["daemonsets"]
    verbs: ["update"]

# Risk: Allowing to create a malicious pod
# Verb: create
# Resources: statefulsets

- kind: Role
  metadata:
    namespace: default
    name: risky-create-statefulsets
    priority: MEDIUM
    description:
      risk: "Allowing to create a malicious pod"
      riskCN: "授权创建statefulsets，引入可疑的pod"
      verb: "create"
      resources: "statefulsets"
  rules:
  - apiGroups: ["*"]
    resources: ["statefulsets"]
    verbs: ["create"]

# Risk: Allowing to update a malicious pod
# Verb: update
# Resources: statefulsets

- kind: Role
  metadata:
    namespace: default
    name: risky-update-statefulsets
    priority: MEDIUM
    description:
      risk: "Allowing to update a malicious pod"
      riskCN: "授权更新statefulsets，引入可疑的pod"
      verb: "create"
      resources: "statefulsets"
  rules:
  - apiGroups: ["*"]
    resources: ["statefulsets"]
    verbs: ["update"]

# Risk: Allowing to create a malicious pod
# Verb: create
# Resources: replicationcontrollers

- kind: Role
  metadata:
    namespace: default
    name: risky-create-replicationcontrollers
    priority: MEDIUM
    description:
      risk: "Allowing to create a malicious pod"
      riskCN: "授权创建replicationcontrollers，引入可疑的pod"
      verb: "create"
      resources: "replicationcontrollers"
  rules:
  - apiGroups: ["*"]
    resources: ["replicationcontrollers"]
    verbs: ["create"]

# Risk: Allowing to update a malicious pod
# Verb: update
# Resources: replicationcontrollers

- kind: Role
  metadata:
    namespace: default
    name: risky-update-replicationcontrollers
    priority: MEDIUM
    description:
      risk: "Allowing to update a malicious pod"
      riskCN: "授权更新replicationcontrollers，引入可疑的pod"
      verb: "update"
      resources: "replicationcontrollers"
  rules:
  - apiGroups: ["*"]
    resources: ["replicationcontrollers"]
    verbs: ["update"]

# Risk: Allowing to create a malicious pod
# Verb: create
# Resources: replicasets

- kind: Role
  metadata:
    namespace: default
    name: risky-create-replicasets
    priority: MEDIUM
    description:
      risk: "Allowing to create a malicious pod"
      riskCN: "授权创建replicasets，引入可疑的pod"
      verb: "create"
      resources: "replicasets"
  rules:
  - apiGroups: ["*"]
    resources: ["replicasets"]
    verbs: ["create"]

# Risk: Allowing to update a malicious pod
# Verb: update
# Resources: replicasets

- kind: Role
  metadata:
    namespace: default
    name: risky-update-replicasets
    priority: MEDIUM
    description:
      risk: "Allowing to update a malicious pod"
      riskCN: "授权更新replicasets，引入可疑的pod"
      verb: "update"
      resources: "replicasets"
  rules:
  - apiGroups: ["*"]
    resources: ["replicasets"]
    verbs: ["update"]

# Risk: Allowing to create a malicious pod
# Verb: create
# Resources: jobs

- kind: Role
  metadata:
    namespace: default
    name: risky-create-jobs
    priority: MEDIUM
    description:
      risk: "Allowing to create a malicious pod"
      riskCN: "授权创建daemonsets，引入可疑的pod"
      verb: "create"
      resources: "jobs"
  rules:
  - apiGroups: ["*"]
    resources: ["jobs"]
    verbs: ["create"]


# Risk: Allowing to update a malicious pod
# Verb: update
# Resources: jobs

- kind: Role
  metadata:
    namespace: default
    name: risky-update-jobs
    priority: MEDIUM
    description:
      risk: "Allowing to update a malicious pod"
      riskCN: "授权更新jobs，引入可疑的pod"
      verb: "update"
      resources: "jobs"
  rules:
  - apiGroups: ["*"]
    resources: ["jobs"]
    verbs: ["update"]

# Risk: Allowing to create a malicious pod
# Verb: create
# Resources: cronjobs

- kind: Role
  metadata:
    namespace: default
    name: risky-create-jobs
    priority: MEDIUM
    description:
      risk: "Allowing to create a malicious pod"
      riskCN: "授权创建cronjobs，引入可疑的pod"
      verb: "create"
      resources: "cronjobs"
  rules:
  - apiGroups: ["*"]
    resources: ["cronjobs"]
    verbs: ["create"]


# Risk: Allowing to update a malicious pod
# Verb: update
# Resources: cronjobs

- kind: Role
  metadata:
    namespace: default
    name: risky-update-jobs
    priority: MEDIUM
    description:
      risk: "Allowing to update a malicious pod"
      riskCN: "授权更新cronjobs，引入可疑的pod"
      verb: "update"
      resources: "cronjobs"
  rules:
  - apiGroups: ["*"]
    resources: ["cronjobs"]
    verbs: ["update"]

# Risk: Allowing creation of rolebinding and associate privileged role to itself
#   GroupA:
#       Verb: create
#       Resource: rolebindings
#   GroupB:
#       Verb: bind
#       Resource: roles
#       resourceNames: privilegedRoles

- kind: Role
  metadata:
    namespace: default
    name: risky-create-rolebinding-role
    priority: HIGH
    description:
      risk: " Allowing creation of rolebinding and associate privileged role to itself"
      riskCN: "允许创建rolebinding，并且将特权role关联到自身"
  rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["create"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles"]
    verbs: ["bind"]
    resourceNames: ["*"]

# Risk: Allowing creation of rolebinding and associate privileged clusterrole to itself
#   GroupA:
#       Verb: create
#       Resource: rolebindings
#   GroupB:
#       Verb: bind
#       Resource: clusterroles
#       resourceNames: privilegedRoles


- kind: Role
  metadata:
    namespace: default
    name: risky-create-rolebinding-clusterrole
    priority: HIGH
    description:
      risk: "Allowing creation of rolebinding and associate privileged clusterrole to itself"
      riskCN: "允许创建rolebinding，并关联特权clusterrole到自身"
  rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["create"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind"]
    resourceNames: ["*"]

# Risk: Allowing creation of clusterrolebinding and associate privileged clusterrole to itself
#   GroupA:
#       Verb: create
#       Resource: clusterrolebinding
#   GroupB:
#       Verb: bind
#       Resource: clusterroles
#       resourceNames: privilegedRoles


- kind: Role
  metadata:
    namespace: default
    name: risky-create-clusterrolebinding-clusterrole
    priority: HIGH
    description:
      risk: "Allowing creation of clusterrolebinding and associate privileged clusterrole to itself"
      riskCN: "允许创建clusterrolebinding，并关联特权clusterrole到自身"
  rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterrolebindings"]
    verbs: ["create"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind"]
    resourceNames: ["*"]

# Risk: Allowing update of a malicious pod
# Verb: create
# Resources: pods
# Example: kubectl create -f malicious-pod.yaml

- kind: Role
  metadata:
    namespace: default
    name: risky-create-pod
    priority: MEDIUM
    description:
      risk: "Allowing update of a malicious pod"
      riskCN: "授权允许创建pods，引入可疑的pod"
      verb: "create"
      resources: "pods"
      example: "kubectl create -f malicious-pod.yaml"
  rules:
  - apiGroups: ["*"]
    resources: ["pods"]
    verbs: ["create"]


# Risk: Getting shell on pods
#   GroupA:
#       Verb: create
#       Resource: pods/exec
#   GroupB:
#       Verb: get
#       Resource: pods
# Example: kubectl exec podname -it sh

- kind: Role
  metadata:
    namespace: default
    name: risky-exec-pods
    priority: HIGH
    description:
      risk: "Getting shell on pods"
      riskCN: "授权在pods上执行shell"
  rules:
  - apiGroups: ["*"]
    resources: ["pods/exec"]
    verbs: ["create"]
  - apiGroups: ["*"]
    resources: ["pods"]
    verbs: ["get"]


# Risk: Attaching pod and view all its logs in realtime
#   GroupA:
#       Verb: create
#       Resource: pods/attach
#   GroupB:
#       Verb: get
#       Resource: pods
# Example: kubectl attach podname -it sh


- kind: Role
  metadata:
    namespace: default
    name: risky-attach-pods
    priority: HIGH
    description:
      risk: "Attaching pod and view all its logs in realtime"
      riskCN: "授权实时查看pods的日志"
  rules:
  - apiGroups: ["*"]
    resources: ["pods/attach"]
    verbs: ["create"]
  - apiGroups: ["*"]
    resources: ["pods"]
    verbs: ["get"]



######################### END REGION - HIGH Roles #########################

# Risk: Privilege Escalation from Node/Proxy
# Verb: get, create
# Resources: nodes/proxy

- kind: Role
  metadata:
    namespace: default
    name: risky-execute-command-node-proxy
    priority: HIGH
    description:
      risk: "Privilege Escalation from Node/Proxy"
      riskCN: "从Node/Proxy权限提升"
      verb: "get, create"
      resources: "nodes/proxy"
  rules:
  - apiGroups: ["*"]
    resources: ["nodes/proxy"]
    verbs: ["get", "create"]


######################### REGION - LOW Roles #########################

# Risk: Allowing users in a rolebinding to add other users to their rolebindings
# Verb: get, patch
# Resources: rolebindings

- kind: Role
  metadata:
    namespace: default
    name: risky-add-rolebinding
    priority: LOW
    description: 
      risk: "Allowing users in a rolebinding to add other users to their rolebindings"
      riskCN: "允许一个rolebindg里的用户添加其他用户到这个rolebinding"
      verb: "get, patch"
      resources: rolebindings
  rules:
  - apiGroups: ["*"]
    resources: ["rolebindings"]
    verbs: ["get", "patch"]

######################### END REGION - LOW Roles #########################

######################### END REGION - Risky permissions combinations #########################`
