package probr

import (
	"github.com/citihub/probr/internal/clouddriver/kubernetes"
	"github.com/citihub/probr/internal/coreengine"

	"github.com/google/uuid"

	_ "github.com/citihub/probr/internal/config" //needed for logging
	"github.com/citihub/probr/test/features"
	_ "github.com/citihub/probr/test/features/clouddriver"                        //needed to run init on TestHandlers
	_ "github.com/citihub/probr/test/features/kubernetes/containerregistryaccess" //needed to run init on TestHandlers
	_ "github.com/citihub/probr/test/features/kubernetes/general"                 //needed to run init on TestHandlers
	_ "github.com/citihub/probr/test/features/kubernetes/internetaccess"          //needed to run init on TestHandlers
	_ "github.com/citihub/probr/test/features/kubernetes/podsecuritypolicy"       //needed to run init on TestHandlers
)

//TODO: revise when interface this bit up ...
var kube = kubernetes.GetKubeInstance()

func addTest(tm *coreengine.TestStore, n string, g coreengine.Group, c coreengine.Category) {

	td := coreengine.TestDescriptor{Group: g, Category: c, Name: n}

	//add - don't worry about the rtn uuid
	tm.AddTest(td)
}

// RunAllTests MUST run after SetIOPaths
func RunAllTests() (int, *coreengine.TestStore, error) {
	tm := coreengine.NewTestManager() // get the test mgr

	//add some tests and add them to the TM - we need to tidy this up!
	addTest(tm, "container_registry_access", coreengine.Kubernetes, coreengine.ContainerRegistryAccess)
	addTest(tm, "internet_access", coreengine.Kubernetes, coreengine.InternetAccess)
	addTest(tm, "pod_security_policy", coreengine.Kubernetes, coreengine.PodSecurityPolicies)
	addTest(tm, "account_manager", coreengine.CloudDriver, coreengine.General)
	addTest(tm, "general", coreengine.Kubernetes, coreengine.General)

	s, err := tm.ExecAllTests() // Executes all added (queued) tests
	return s, tm, err
}

//GetAllTestResults ...
func GetAllTestResults(ts *coreengine.TestStore) (map[string]string, error) {
	out := make(map[string]string)
	for id := range ts.Tests {
		r, n, err := ReadTestResults(ts, id)
		if err != nil {
			return nil, err
		}
		if r != "" {
			out[n] = r
		}
	}
	return out, nil
}

//ReadTestResults ...
func ReadTestResults(ts *coreengine.TestStore, id uuid.UUID) (string, string, error) {
	t, err := ts.GetTest(&id)
	test := (*t)[0]
	ts.AuditLog.Audit(id.String(), "status", test.Status.String())
	if err != nil {
		return "", "", err
	}
	r := test.Results
	n := test.TestDescriptor.Name
	if r != nil {
		b := r.Bytes()
		return string(b), n, nil
	}
	return "", "", nil
}

// SetIOPaths ...
func SetIOPaths(i string, o string) {
	features.SetOutputDirectory(&o)
}
