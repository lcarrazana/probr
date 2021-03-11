// Package iam provides the implementation required to execute the BDD tests described in iam.feature file
package iam

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/cucumber/godog"
	apiv1 "k8s.io/api/core/v1"

	"github.com/citihub/probr/audit"
	"github.com/citihub/probr/config"
	"github.com/citihub/probr/service_packs/coreengine"
	"github.com/citihub/probr/service_packs/kubernetes"
	"github.com/citihub/probr/service_packs/kubernetes/connection"
	"github.com/citihub/probr/service_packs/kubernetes/constructors"
	"github.com/citihub/probr/utils"
)

type probeStruct struct{}

// scenarioState holds the steps and state for any scenario in this probe
type scenarioState struct {
	name         string
	currentStep  string
	namespace    string
	probe        *audit.Probe
	audit        *audit.ScenarioAudit
	pods         []string
	podState     kubernetes.PodState //TODO: Remove
	useDefaultNS bool                // TODO: Remove
}

// Probe meets the service pack interface for adding the logic from this file
var Probe probeStruct
var scenario scenarioState
var conn connection.Connection

// ProbeCommand defines commands for use in testing IAM
type ProbeCommand int

// enum supporting ProbeCommand
const (
	CatAzJSON ProbeCommand = iota
	CurlAuthToken
)

func (c ProbeCommand) String() string {
	return [...]string{"cat /etc/kubernetes/azure.json",
		"curl http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F -H Metadata:true -s"}[c]
}

// IdentityAccessManagement is the section of the kubernetes package which provides the kubernetes interactions required to support
// identity access management scenarios.
var iam IdentityAccessManagement // TODO: Remove

// SetIAM allows injection of an IdentityAccessManagement helper.
func SetIAM(i IdentityAccessManagement) { // TODO: Remove
	iam = i
}

// azureIdentitySetupCheck executes the provided function and returns a formatted error
func (scenario *scenarioState) azureIdentitySetupCheck(f func(arg1 string, arg2 string) (bool, error), namespace, resourceType, resourceName string) error {
	//TODO: Remove and make explicit checks
	b, err := f(namespace, resourceName)

	if err != nil {
		err = utils.ReformatError("error raised when checking for %v: %v", resourceType, err)
		log.Print(err)
		return err
	}

	if !b {
		err = utils.ReformatError("%v does not exist (result: %t)", resourceType, b)
		log.Print(err)
		return err
	}

	return nil
}

func (scenario *scenarioState) aKubernetesClusterIsDeployed() error {
	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()
	stepTrace.WriteString(fmt.Sprintf("Validate that a cluster can be reached using the specified kube config and context; "))

	payload = struct {
		KubeConfigPath string
		KubeContext    string
	}{
		config.Vars.ServicePacks.Kubernetes.KubeConfigPath,
		config.Vars.ServicePacks.Kubernetes.KubeContext,
	}

	err = conn.ClusterIsDeployed() // Must be assigned to 'err' be audited
	return err
}

//AZ-AAD-AI-1.0
func (s *scenarioState) aNamedAzureIdentityBindingExistsInNamedNSOld(aibName string, namespace string) error {
	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		s.audit.AuditScenarioStep(s.currentStep, stepTrace.String(), payload, err)
	}()

	stepTrace.WriteString(fmt.Sprintf(
		"Check whether '%s' Azure Identity Binding exists in namespace '%s'; ", aibName, namespace))
	err = s.azureIdentitySetupCheck(iam.AzureIdentityBindingExists, namespace, "AzureIdentityBinding", aibName)

	return err
}

func (scenario *scenarioState) aNamedAzureIdentityBindingExistsInNamedNS(aibName string, namespace string) error {

	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	// TODO: Some issues with this:
	// - This implementation is coupled to Azure.
	// - It is used for dealing with Azure Custom Resource Definition. Should we use available package instead? See: https://pkg.go.dev/github.com/Azure/aad-pod-identity@v1.6.3/pkg/apis/aadpodidentity

	// Azure Identity Bindings are implemented as K8s Custom Resource Definition
	// Need to make a 'raw' call to the corresponding K8s endpoint
	// The K8s api endpoint for AIB's is: "apis/aadpodidentity.k8s.io/v1/azureidentitybindings"
	aadpodidentityAPIEndpoint := "apis/aadpodidentity.k8s.io/v1/azureidentitybindings"

	stepTrace.WriteString(fmt.Sprintf(
		"Retrieve Azure Identity Bindings from cluster using api endpoint '%s'; ", aadpodidentityAPIEndpoint))
	azureidentitybindings, getError := conn.GetRawResourcesByAPIEndpoint(aadpodidentityAPIEndpoint)
	if getError != nil {
		err = utils.ReformatError("An error occured while retrieving Azure Identity Bindings from K8s cluster: %v", getError)
		return err
	}

	stepTrace.WriteString(fmt.Sprintf(
		"Check that Azure Identity Binding '%s' exists in namespace '%s'; ", aibName, namespace))
	found := false
	for _, azureIdentityBinding := range azureidentitybindings.Items {
		if (azureIdentityBinding.Metadata["namespace"] == namespace) && (azureIdentityBinding.Metadata["name"] == aibName) {
			found = true
			break
		}
	}
	if !found {
		err = utils.ReformatError("Azure Identity Binding '%s' was not found in namespace '%s'; ", aibName, namespace)
		return err
	}

	payload = struct {
		AADIdentityBindings connection.K8SJSON
	}{
		AADIdentityBindings: azureidentitybindings,
	}

	return err
}

func (scenario *scenarioState) iSucceedToCreateASimplePodInNamespaceAssignedWithThatAzureIdentityBinding(namespace, aibName string) error {
	// Supported values for namespace:
	//  'the probr'
	//	'the default'
	//
	// Supported values for aibName:
	//	'probr-aib'

	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	// Validate input
	switch aibName {
	case "probr-aib":
	default:
		err = utils.ReformatError("Unexpected value provided for aibName: %s", aibName)
		return err
	}

	var aadPodIDBinding string

	// Validate input
	switch namespace {
	case "the probr":
		aadPodIDBinding = aibName // TODO: This value is the same in both config and feature file
	case "the default":
		scenario.namespace = "default"
		aadPodIDBinding = config.Vars.ServicePacks.Kubernetes.Azure.DefaultNamespaceAIB // TODO: This value is the same in both config and feature file
	default:
		err = utils.ReformatError("Unexpected value provided for namespace: %s", namespace)
		return err
	}

	stepTrace.WriteString(fmt.Sprintf("Build a pod spec with default values; "))
	securityContext := constructors.DefaultContainerSecurityContext()
	podObject := constructors.PodSpec(Probe.Name(), config.Vars.ServicePacks.Kubernetes.ProbeNamespace, securityContext)
	// TODO: Do we need spec:nodeSelector:kubernetes.io/os: linux ? This is the only diff with iam-azi-test-aib-curl.yaml

	stepTrace.WriteString(fmt.Sprintf("Add '%s' namespace to pod spec; ", scenario.namespace))
	podObject.Namespace = scenario.namespace

	stepTrace.WriteString(fmt.Sprintf("Add 'aadpodidbinding':'%s' label to pod spec; ", aadPodIDBinding))
	// For a pod to use AAD pod-managed identity, the pod needs an aadpodidbinding label with a value that matches a selector from a AzureIdentityBinding.
	// Ref: https://docs.microsoft.com/en-us/azure/aks/use-azure-ad-pod-identity
	podObject.Labels["aadpodidbinding"] = aadPodIDBinding

	stepTrace.WriteString(fmt.Sprintf("Create pod from spec; "))
	createdPodObject, creationErr := scenario.createPodfromObject(podObject)

	stepTrace.WriteString("Validate pod creation succeeds; ")
	if creationErr != nil {
		err = utils.ReformatError("Pod creation did not succeed: %v", creationErr)
	}

	payload = struct {
		Namespace      string
		AADPodIdentity string
		RequestedPod   *apiv1.Pod
		CreatedPod     *apiv1.Pod
		CreationError  error
	}{
		Namespace:      scenario.namespace,
		AADPodIdentity: aadPodIDBinding,
		RequestedPod:   podObject,
		CreatedPod:     createdPodObject,
		CreationError:  creationErr,
	}

	return err
}

func (scenario *scenarioState) anAttemptToObtainAnAccessTokenFromThatPodShouldFail() error {

	//reuse the parameterised / scenario outline func
	// TODO: Suggestion: Remove this function and leverage existing step in k-iam-001 with 'Fail' as parameter
	// E.g: But an attempt to obtain an access token from that pod should "Fail"
	return scenario.anAttemptToObtainAnAccessTokenFromThatPodShould("Fail")
}

func (scenario *scenarioState) anAttemptToObtainAnAccessTokenFromThatPodShould(expectedResult string) error {
	// Supported values for expectedResult:
	//	'Fail'
	//  'Succeed'

	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	// Validate input
	var shouldReturnToken bool
	switch expectedResult {
	case "Fail":
		shouldReturnToken = false
	case "Succeed":
		shouldReturnToken = true
	default:
		err = utils.ReformatError("Unexpected value provided for expectedResult: %s", expectedResult)
		return err
	}

	// Guard clause: Ensure pod was created in previous step
	if len(scenario.pods) == 0 {
		err = utils.ReformatError("Pod failed to create in the previous step")
		return err
	}

	podName := scenario.pods[0]

	// Mechanism to get access token is executing a curl command on the pod
	// TODO: Clarify this and fix
	cmd := "curl http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F -H Metadata:true -s"

	stepTrace.WriteString(fmt.Sprintf("Attempt to run command in the pod: '%s'; ", cmd))
	_, stdOut, cmdErr := conn.ExecCommand(cmd, scenario.namespace, podName)

	// Validate that no internal error occurred during execution of curl command
	if cmdErr != nil {
		err = utils.ReformatError("Error raised when attempting to execute curl command inside container: %v", cmdErr)
		return err
	}

	stepTrace.WriteString("Attempt to extract access token from command output; ")
	var accessToken struct {
		AccessToken string `json:"access_token,omitempty"`
	}
	jsonConvertErr := json.Unmarshal([]byte(stdOut), &accessToken)

	switch shouldReturnToken {
	case true:
		stepTrace.WriteString("Validate token was found; ")
		if jsonConvertErr != nil {
			err = utils.ReformatError("Failed to acquire token on pod %v Error: %v StdOut: %s", podName, jsonConvertErr, stdOut)
		}
		if &accessToken.AccessToken == nil {
			err = utils.ReformatError("Failed to acquire token on pod %v", podName)
		}
	case false:
		stepTrace.WriteString("Validate no token was found; ") //TODO: Was previously getting false-positive. Now is failing as it is supposed to.
		if jsonConvertErr != nil && &accessToken.AccessToken == nil && len(accessToken.AccessToken) > 0 {
			err = utils.ReformatError("Token was successfully acquired on pod %v (result: %v)", podName, accessToken.AccessToken) //TODO: Remove access token from output for security reasons
		}
	}

	return err
}

//AZ-AAD-AI-1.1
func (scenario *scenarioState) aNamedAzureIdentityExistsInNamedNS(namespace string, aiName string) error {
	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	stepTrace.WriteString(fmt.Sprintf(
		"Validate that '%s' identity is found in '%s' namespace; ",
		aiName,
		namespace))
	err = scenario.azureIdentitySetupCheck(iam.AzureIdentityExists, namespace, "AzureIdentity", aiName)

	payload = struct {
		PodState kubernetes.PodState
	}{scenario.podState}

	return err
}

func (scenario *scenarioState) iCreateAnAzureIdentityBindingCalledInANondefaultNamespace(aibName, aiName string) error {
	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	stepTrace.WriteString(fmt.Sprintf(
		"Attempt to create '%s' binding in the Probr namespace bound to '%s' identity; ", aibName, aiName))
	err = iam.CreateAIB(false, aibName, aiName) // create an AIB in a non-default NS if it deosn't already exist
	if err != nil {
		err = utils.ReformatError("error returned from CreateAIB: %v", err)
		log.Print(err)
	}

	payload = struct {
		PodState kubernetes.PodState
	}{scenario.podState}
	return err
}

func (scenario *scenarioState) iDeployAPodAssignedWithTheAzureIdentityBindingIntoTheProbrNameSpace(aibName string) error {
	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	specPath := "iam-azi-test-aib-curl.yaml"
	stepTrace.WriteString(fmt.Sprintf(
		"Get pod spec from '%s'; ", specPath))
	y, err := utils.ReadStaticFile(kubernetes.AssetsDir, specPath)
	if err != nil {
		err = utils.ReformatError("error reading yaml for test: %v", err)
		log.Print(err)
	} else {
		stepTrace.WriteString(fmt.Sprintf(
			"Attempt to deploy pod with '%s' binding to the Probr namespace; ", aibName))
		pd, err := iam.CreateIAMProbePod(y, false, aibName, scenario.probe)
		err = kubernetes.ProcessPodCreationResult(&scenario.podState, pd, kubernetes.UndefinedPodCreationErrorReason, err)
	}

	payload = struct {
		PodState       kubernetes.PodState
		PodName        string
		ProbrNameSpace string
	}{scenario.podState, scenario.podState.PodName, kubernetes.Namespace}

	return err
}

//AZ-AAD-AI-1.2
func (scenario *scenarioState) theClusterHasManagedIdentityComponentsDeployed() error {

	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	identityPodsNamespace := getAzureIdentityNamespaceFromConfig()
	stepTrace.WriteString(fmt.Sprintf(
		"Get pods from '%s' namespace; ", identityPodsNamespace))
	//look for the mic pods in the default ns
	pl, err := kubernetes.GetKubeInstance().GetPods(identityPodsNamespace)

	if err != nil {
		err = utils.ReformatError("error raised when trying to retrieve pods %v", err)
	} else {
		stepTrace.WriteString("Validate that Cluster has managed identity component deployed by checking whether a pod with 'mic-' prefix is found; ")
		//a "pass" is the prescence of a "mic*" pod(s)
		//break on the first ...
		micCount := 0
		for _, pd := range pl.Items {
			if strings.Contains(pd.Name, "mic-") {
				//grab the pod name as we'll execute the cmd against this:
				scenario.podState.PodName = pd.Name
				micCount = micCount + 1
			}
		}
		if micCount == 0 {
			err = utils.ReformatError("no MIC pods found - test fail")
		} else {
			err = nil
		}
	}

	payload = struct {
		PodState kubernetes.PodState
	}{scenario.podState}

	return err
}

func (scenario *scenarioState) iExecuteTheCommandAgainstTheMICPod(arg1 string) error {
	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	identityPodsNamespace := getAzureIdentityNamespaceFromConfig()
	stepTrace.WriteString(fmt.Sprintf(
		"Attempt to execute command '%s'; ", CatAzJSON.String()))
	res, err := iam.ExecuteVerificationCmd(scenario.podState.PodName, CatAzJSON, identityPodsNamespace)

	if err != nil {
		//this is an error from trying to execute the command as opposed to
		//the command itself returning an error
		err = utils.ReformatError("error raised trying to execute verification command (%v) - %v", CatAzJSON, err)
		log.Print(err)
	} else if res == nil {
		err = utils.ReformatError("<nil> result received when trying to execute verification command (%v)", CatAzJSON)
		log.Print(err)
	} else if res.Err != nil && res.Internal {
		//we have an error which was raised before reaching the cluster (i.e. it's "internal")
		//this indicates that the command was not successfully executed
		err = utils.ReformatError("%s: %v - (%v)", utils.CallerName(0), CatAzJSON, res.Err)
		log.Print(err)
	}
	stepTrace.WriteString(fmt.Sprintf(
		"Store '%v' exit code in scenario state; ", res.Code))
	scenario.podState.CommandExitCode = res.Code

	payload = struct {
		PodState kubernetes.PodState
	}{scenario.podState}

	return err
}

func (scenario *scenarioState) kubernetesShouldPreventMeFromRunningTheCommand() error {
	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	stepTrace.WriteString("Examine scenario state to ensure that verification command exit code was not 0; ")
	if scenario.podState.CommandExitCode == 0 {
		err = utils.ReformatError("verification command was not blocked")
	}

	payload = struct {
		PodState kubernetes.PodState
	}{scenario.podState}

	return err
}

// Name presents the name of this probe for external reference
func (p probeStruct) Name() string {
	return "iam"
}

// Path presents the path of these feature files for external reference
func (p probeStruct) Path() string {
	return coreengine.GetFeaturePath("service_packs", "kubernetes", p.Name())
}

// ProbeInitialize handles any overall Test Suite initialisation steps.  This is registered with the
// test handler as part of the init() function.
func (p probeStruct) ProbeInitialize(ctx *godog.TestSuiteContext) {
	ctx.BeforeSuite(func() {
		conn = connection.Get()

		// TODO: Remove
		//check dependancies ...
		if iam == nil {
			// not been given one so set default
			iam = NewDefaultIAM()
		}
		//setup AzureIdentity stuff ..??  Or should this be a pre-test setup
		// psp.CreateConfigMap()
	})

	ctx.AfterSuite(func() {
		//tear down AzureIdentity stuff?
		// psp.DeleteConfigMap()
	})
}

// ScenarioInitialize initialises the specific test steps.  This is essentially the creation of the test
// which reflects the tests described in the events directory.  There must be a test step registered for
// each line in the feature files. Note: Godog will output stub steps and implementations if it doesn't find
// a step / function defined.  See: https://github.com/cucumber/godog#example.
func (p probeStruct) ScenarioInitialize(ctx *godog.ScenarioContext) {

	ps := scenarioState{}

	ctx.BeforeScenario(func(s *godog.Scenario) {
		beforeScenario(&ps, p.Name(), s)
	})

	// Background
	ctx.Step(`^a Kubernetes cluster exists which we can deploy into$`, ps.aKubernetesClusterIsDeployed)

	// Steps
	ctx.Step(`^an AzureIdentityBinding called "([^"]*)" exists in the namespace called "([^"]*)"$`, ps.aNamedAzureIdentityBindingExistsInNamedNS)
	ctx.Step(`^I succeed to create a simple pod in "([^"]*)" namespace assigned with the "([^"]*)" AzureIdentityBinding$`, ps.iSucceedToCreateASimplePodInNamespaceAssignedWithThatAzureIdentityBinding)
	ctx.Step(`^an attempt to obtain an access token from that pod should "([^"]*)"$`, ps.anAttemptToObtainAnAccessTokenFromThatPodShould)

	//AZ-AAD-AI-1.1 (same as above but just single shot scenario)
	ctx.Step(`^an attempt to obtain an access token from that pod should fail$`, ps.anAttemptToObtainAnAccessTokenFromThatPodShouldFail)

	//AZ-AAD-AI-1.1
	ctx.Step(`^the namespace called "([^"]*)" has an AzureIdentity called "([^"]*)"$`, ps.aNamedAzureIdentityExistsInNamedNS)
	ctx.Step(`^I create an AzureIdentityBinding called "([^"]*)" in the Probr namespace bound to the "([^"]*)" AzureIdentity$`, ps.iCreateAnAzureIdentityBindingCalledInANondefaultNamespace)
	ctx.Step(`^I deploy a pod assigned with the "([^"]*)" AzureIdentityBinding into the Probr namespace$`, ps.iDeployAPodAssignedWithTheAzureIdentityBindingIntoTheProbrNameSpace)

	//AZ-AAD-AI-1.2
	ctx.Step(`^I execute the command "([^"]*)" against the MIC pod$`, ps.iExecuteTheCommandAgainstTheMICPod)
	ctx.Step(`^Kubernetes should prevent me from running the command$`, ps.kubernetesShouldPreventMeFromRunningTheCommand)
	ctx.Step(`^the cluster has managed identity components deployed$`, ps.theClusterHasManagedIdentityComponentsDeployed)

	ctx.AfterScenario(func(s *godog.Scenario, err error) {
		iam.DeleteIAMProbePod(ps.podState.PodName, ps.useDefaultNS, p.Name())
		coreengine.LogScenarioEnd(s)
		//afterScenario(ps, p, s, err)
	})

	ctx.BeforeStep(func(st *godog.Step) {
		ps.currentStep = st.Text
	})

	ctx.AfterStep(func(st *godog.Step, err error) {
		ps.currentStep = ""
	})
}

func beforeScenario(s *scenarioState, probeName string, gs *godog.Scenario) {
	s.name = gs.Name
	s.probe = audit.State.GetProbeLog(probeName)
	s.audit = audit.State.GetProbeLog(probeName).InitializeAuditor(gs.Name, gs.Tags)
	s.pods = make([]string, 0)
	s.namespace = config.Vars.ServicePacks.Kubernetes.ProbeNamespace
	coreengine.LogScenarioStart(gs)
}

func afterScenario(scenario scenarioState, probe probeStruct, gs *godog.Scenario, err error) {
	if kubernetes.GetKeepPodsFromConfig() == false {
		for _, podName := range scenario.pods {
			err = conn.DeletePodIfExists(podName, scenario.namespace, probe.Name())
			if err != nil {
				log.Printf(fmt.Sprintf("[ERROR] Could not retrieve pod from namespace '%s' for deletion: %s", scenario.namespace, err))
			}
		}
	}
	coreengine.LogScenarioEnd(gs)
}

func getAzureIdentityNamespaceFromConfig() string {
	// TODO: Caution, this looks like an explicit dependency on Azure. Confirm workaround exists to decouple.
	return config.Vars.ServicePacks.Kubernetes.Azure.IdentityNamespace
}

func (scenario *scenarioState) createPodfromObject(podObject *apiv1.Pod) (createdPodObject *apiv1.Pod, err error) {
	createdPodObject, err = conn.CreatePodFromObject(podObject, Probe.Name())
	if err == nil {
		scenario.pods = append(scenario.pods, createdPodObject.ObjectMeta.Name)
	}
	return
}
