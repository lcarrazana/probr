package kubernetespack

var (
	tags = map[string][]string{
		"@probes/kubernetes":                           {"k-cra", "k-gen", "k-iam", "k-iaf", "k-psp"},
		"@probes/kubernetes/general":                   {"k-gen"},
		"@probes/kubernetes/iam":                       {"k-iam"},
		"@standard/citihub/CHC2-APPDEV135":             {"k-cra"},
		"@standard/citihub/CHC2-ITS120":                {"k-cra"},
		"@control_type/preventative":                   {"k-cra-001", "k-cra-002", "k-cra-003", "k-iam-001", "k-iam-002", "k-iam-003", "k-iaf-001", "k-psp-001", "k-psp-002", "k-psp-003", "k-psp-004", "k-psp-005", "k-psp-006", "k-psp-007", "k-psp-008", "k-psp-009", "k-psp-010", "k-psp-011", "k-psp-012", "k-psp-013"},
		"@standard/cis":                                {"k-gen", "k-psp"},
		"@standard/cis/gke":                            {"k-gen", "k-psp"},
		"@standard/cis/gke/v1.6.0/5.1.3":               {"k-gen-001"},
		"@standard/cis/gke/v1.6.0/5.6.3":               {"k-gen-002"},
		"@standard/cis/gke/v1.6.0/6":                   {"k-cra"},
		"@standard/cis/gke/v1.6.0/6.1":                 {"k-cra"},
		"@standard/cis/gke/v1.6.0/6.1.3":               {"k-cra-001"},
		"@standard/cis/gke/v1.6.0/6.1.4":               {"k-cra-002"},
		"@standard/cis/gke/v1.6.0/6.1.5":               {"k-cra-003"},
		"@standard/cis/gke/v1.6.0/6.10.1":              {"k-gen-003"},
		"@csp/any":                                     {"k-cra", "k-gen", "k-iam", "k-psp"},
		"@csp/azure":                                   {"k-iam-001", "k-iam-002", "k-iam-003"},
		"@probes/kubernetes/container_registry_access": {"k-cra"},
		"@control_type/inspection":                     {"k-gen-001", "k-gen-002", "k-gen-003"},
		"@standard/citihub/CHC2-IAM105":                {"k-gen-001", "k-iam", "k-psp"},
		"@standard/citihub/CHC2-ITS115":                {"k-gen-003"},
		"@standard/citihub/CHC2-SVD010":                {"k-iaf"},
		"@category/iam":                                {"k-iam"},
		"@standard/citihub":                            {"k-iam", "k-iaf", "k-psp"},
		"@probes/kubernetes/pod_security_policy":       {"k-psp"},
		"@category/pod_security_policy":                {"k-psp"},
		"@standard/cis/gke/v1.6.0/5":                   {"k-psp"},
		"@standard/cis/gke/v1.6.0/5.2":                 {"k-psp"},
		"@standard/cis/gke/v1.6.0/5.2.1":               {"k-psp-001"},
		"@standard/cis/gke/v1.6.0/5.2.2":               {"k-psp-002"},
		"@standard/cis/gke/v1.6.0/5.2.3":               {"k-psp-003"},
		"@standard/cis/gke/v1.6.0/5.2.4":               {"k-psp-004"},
		"@standard/cis/gke/v1.6.0/5.2.5":               {"k-psp-005"},
		"@standard/cis/gke/v1.6.0/5.2.6":               {"k-psp-006"},
		"@standard/cis/gke/v1.6.0/5.2.7":               {"k-psp-007", "k-psp-013"},
		"@standard/cis/gke/v1.6.0/5.2.8":               {"k-psp-008"},
		"@standard/cis/gke/v1.6.0/5.2.9":               {"k-psp-009"},
		"@standard/none/PSP-0.1":                       {"k-psp-012"},
	}
)
