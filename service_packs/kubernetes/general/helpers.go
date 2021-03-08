package general

import (
	apiv1 "k8s.io/api/core/v1"

	"github.com/citihub/probr/audit"
	"github.com/citihub/probr/config"
	"github.com/citihub/probr/service_packs/kubernetes"
)

const (
	defaultNAProbeContainer = "na-test"
	defaultNAProbePodName   = "na-test-pod"
)

// NetworkAccess defines functionality for supporting Network Access tests.
type NetworkAccess interface {
	SetupNetworkAccessProbePod(probe *audit.Probe) (*apiv1.Pod, *kubernetes.PodAudit, error)
}

// NA implements NetworkAccess.
type NA struct {
	k kubernetes.Kubernetes

	probeImage     string
	probeContainer string
	probePodName   string
}

// NewNA creates a new instance of NA with the supplied kubernetes instance.
func NewNA(k kubernetes.Kubernetes) *NA {
	n := &NA{}
	n.k = k

	n.setup()
	return n
}

// NewDefaultNA creates a new instance of NA using the default kubernetes instance.
func NewDefaultNA() *NA {
	n := &NA{}
	n.k = kubernetes.GetKubeInstance()

	n.setup()
	return n
}

func (n *NA) setup() {

	//just default these for now (not sure we'll ever want to supply):
	n.probeContainer = defaultNAProbeContainer
	n.probePodName = defaultNAProbePodName

	// Extract registry and image info from config
	n.probeImage = config.Vars.ServicePacks.Kubernetes.AuthorisedContainerRegistry + "/" + config.Vars.ServicePacks.Kubernetes.ProbeImage
}

// SetupNetworkAccessProbePod creates a pod with characteristics required for testing network access.
func (n *NA) SetupNetworkAccessProbePod(probe *audit.Probe) (*apiv1.Pod, *kubernetes.PodAudit, error) {
	pname, ns, cname, image := kubernetes.GenerateUniquePodName(n.probePodName), kubernetes.Namespace, n.probeContainer, n.probeImage
	//let caller handle result:
	return n.k.CreatePod(pname, ns, cname, image, true, nil, probe)
}
