// Package general provides the implementation required to execute the feature-based test cases
// described in the the 'events' directory.
package general

import (
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	apiv1 "k8s.io/api/core/v1"

	"github.com/cucumber/godog"

	"github.com/citihub/probr/audit"
	"github.com/citihub/probr/config"
	"github.com/citihub/probr/service_packs/coreengine"
	"github.com/citihub/probr/service_packs/kubernetes"
	"github.com/citihub/probr/service_packs/kubernetes/connection"
	"github.com/citihub/probr/service_packs/kubernetes/constructors"
	"github.com/citihub/probr/utils"
)

type probeStruct struct{}

var conn connection.Connection

type scenarioState struct {
	name        string
	currentStep string
	namespace   string
	audit       *audit.ScenarioAudit
	probe       *audit.Probe
	pods        []string
}

// Probe meets the service pack interface for adding the logic from this file
var Probe probeStruct
var scenario scenarioState

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

// TODO: Confirm 330
// //@CIS-5.1.3
// // I inspect the "<Roles / Cluster Roles>" that are configured
// func (scenario *scenarioState) iInspectTheThatAreConfigured(roleLevel string) error {
// 	stepTrace, payload, err := utils.AuditPlaceholders()
// 	defer func() {
// 		// Standard auditing logic to ensures panics are also audited
// 		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
// 	}()

// 	if roleLevel == "Cluster Roles" {
// 		stepTrace.WriteString("Retrieving instance cluster roles; ")
// 		l, e := kubernetes.GetKubeInstance().GetClusterRolesByResource("*")
// 		err = e
// 		scenario.wildcardRoles = l
// 	} else if roleLevel == "Roles" {
// 		stepTrace.WriteString("Retrieving instance roles; ")
// 		l, e := kubernetes.GetKubeInstance().GetRolesByResource("*")
// 		err = e
// 		scenario.wildcardRoles = l
// 	}
// 	if err != nil {
// 		err = utils.ReformatError("Could not retrieve role level '%v': %v", roleLevel, err)
// 	}

// 	stepTrace.WriteString("Stored any retrieved wildcard roles in state for following steps; ")
// 	payload = struct {
// 		PodState kubernetes.PodState
// 	}{scenario.podState}
// 	return err
// }

// TODO: Confirm 330
// func (scenario *scenarioState) iShouldOnlyFindWildcardsInKnownAndAuthorisedConfigurations() error {
// 	// Standard auditing logic to ensures panics are also audited
// 	stepTrace, payload, err := utils.AuditPlaceholders()
// 	defer func() {
// 		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
// 	}()

// 	//we strip out system/known entries in the cluster roles & roles call
// 	var wildcardCount int
// 	//	wildcardCount := len(s.wildcardRoles.([]interface{}))
// 	stepTrace.WriteString("Removing known entries from the cluster roles; ")
// 	switch scenario.wildcardRoles.(type) {
// 	case *[]v1.Role:
// 		wildCardRoles := scenario.wildcardRoles.(*[]rbacv1.Role)
// 		wildcardCount = len(*wildCardRoles)
// 	case *[]v1.ClusterRole:
// 		wildCardRoles := scenario.wildcardRoles.(*[]rbacv1.ClusterRole)
// 		wildcardCount = len(*wildCardRoles)
// 	default:
// 	}

// 	stepTrace.WriteString("Validate that no unexpected wildcards were found; ")
// 	if wildcardCount > 0 {
// 		err = utils.ReformatError("roles exist with wildcarded resources")
// 	}

// 	payload = struct {
// 		PodState kubernetes.PodState
// 	}{scenario.podState}

// 	return err
// }

// TODO: Confirm 330
// //@CIS-5.6.3
// func (scenario *scenarioState) iAttemptToCreateADeploymentWhichDoesNotHaveASecurityContext() error {
// 	// Standard auditing logic to ensures panics are also audited
// 	stepTrace, payload, err := utils.AuditPlaceholders()
// 	defer func() {
// 		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
// 	}()

// 	stepTrace.WriteString("Create unique pod name; ")
// 	cname := "probr-general"
// 	podName := kubernetes.GenerateUniquePodName(cname)

// 	stepTrace.WriteString("Attempt to deploy ProbeImage without a security context; ")
// 	image := config.Vars.ServicePacks.Kubernetes.AuthorisedContainerRegistry + "/" + config.Vars.ServicePacks.Kubernetes.ProbeImage
// 	pod, podAudit, err := kubernetes.GetKubeInstance().CreatePod(podName, "probr-general-test-ns", cname, image, true, nil, scenario.probe)

// 	stepTrace.WriteString(fmt.Sprintf(
// 		"Ensure failure to deploy returns '%s'; ", kubernetes.UndefinedPodCreationErrorReason))
// 	err = kubernetes.ProcessPodCreationResult(&scenario.podState, pod, kubernetes.UndefinedPodCreationErrorReason, err)

// 	payload = kubernetes.PodPayload{Pod: pod, PodAudit: podAudit}
// 	return err
// }

// TODO: Confirm 330
// func (scenario *scenarioState) theDeploymentIsRejected() error {
// 	// Standard auditing logic to ensures panics are also audited
// 	stepTrace, payload, err := utils.AuditPlaceholders()
// 	defer func() {
// 		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
// 	}()

// 	//looking for a non-nil creation error
// 	if scenario.podState.CreationError == nil {
// 		err = utils.ReformatError("pod %v was created successfully. Test fail.", scenario.podState.PodName)
// 	}

// 	stepTrace.WriteString("Validates that an expected creation error occurred in the previous step; ")
// 	payload = struct {
// 		PodState kubernetes.PodState
// 	}{scenario.podState}

// 	return err
// }

// TODO: Confirm 331
// //@CIS-6.10.1
// // PENDING IMPLEMENTATION
// func (scenario *scenarioState) iShouldNotBeAbleToAccessTheKubernetesWebUI() error {
// 	//TODO: will be difficult to test this.  To access it, a proxy needs to be created:
// 	//az aks browse --resource-group rg-probr-all-policies --name ProbrAllPolicies
// 	//which will then open a browser at:
// 	//http://127.0.0.1:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/#/login
// 	//I don't think this is going to be easy to do from here
// 	//Is there another test?  Or is it sufficient to verify that no kube-dashboard is running?

// 	// Standard auditing logic to ensures panics are also audited
// 	stepTrace, payload, err := utils.AuditPlaceholders()
// 	defer func() {
// 		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
// 	}()
// 	stepTrace.WriteString("PENDING IMPLEMENTATION")
// 	return godog.ErrPending
// }

func (scenario *scenarioState) theKubernetesWebUIIsDisabled() error {

	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	kubeSystemNamespace, dashboardPodNamePrefix := getKubeSystemNamespaceAndDashboardPodNamePrefixFromConfig()
	stepTrace.WriteString(fmt.Sprintf("Attempt to find a pod in the '%s' namespace with the prefix '%s'; ", kubeSystemNamespace, dashboardPodNamePrefix))

	stepTrace.WriteString(fmt.Sprintf("Get all pods from '%s' namespace; ", kubeSystemNamespace))
	podList, getError := conn.GetPodsByNamespace(kubeSystemNamespace) // Also validates if provided namespace is valid
	if getError != nil {
		err = utils.ReformatError("An error occurred while retrieving pods from '%s' namespace. Error: %s", kubeSystemNamespace, getError)
		return err
	}

	stepTrace.WriteString(fmt.Sprintf("Confirm a pod with '%s' prefix doesn't exist; ", dashboardPodNamePrefix))
	for _, pod := range podList.Items {
		if strings.HasPrefix(pod.Name, dashboardPodNamePrefix) {
			err = utils.ReformatError("Dashboard UI Pod was found: '%s'", pod.Name)
			break
		}
	}

	payload = struct {
		KubeSystemNamespace    string
		DashboardPodNamePrefix string
	}{
		KubeSystemNamespace:    kubeSystemNamespace,
		DashboardPodNamePrefix: dashboardPodNamePrefix,
	}

	return err
}

// NetworkAccess is the section of the kubernetes package which provides the kubernetes interactions required to support
// network access scenarios.
//var na NetworkAccess

// SetNetworkAccess allows injection of a specific NetworkAccess helper.
// func SetNetworkAccess(n NetworkAccess) {
// 	na = n
// }

func (scenario *scenarioState) aPodIsDeployedInTheCluster() error {

	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	stepTrace.WriteString(fmt.Sprintf("Build a pod spec with default values; "))
	securityContext := constructors.DefaultContainerSecurityContext()
	podObject := constructors.PodSpec(Probe.Name(), config.Vars.ServicePacks.Kubernetes.ProbeNamespace, securityContext)

	stepTrace.WriteString(fmt.Sprintf("Create pod from spec; "))
	createdPodObject, creationErr := scenario.createPodfromObject(podObject)

	if creationErr != nil {
		err = utils.ReformatError("Pod creation did not succeed: %v", creationErr)
	}

	payload = struct {
		RequestedPod  *apiv1.Pod
		CreatedPod    *apiv1.Pod
		CreationError error
	}{
		RequestedPod:  podObject,
		CreatedPod:    createdPodObject,
		CreationError: creationErr,
	}

	return err
}

func (scenario *scenarioState) theResultOfAProcessInsideThePodEstablishingADirectHTTPConnectionToXIsY(urlAddress, result string) error {
	// Supported values for urlAddress:
	//	A valid absolute path URL with or without http(s) prefix
	//
	// Supported values for result:
	//	'blocked'

	// Standard auditing logic to ensures panics are also audited
	stepTrace, payload, err := utils.AuditPlaceholders()
	defer func() {
		scenario.audit.AuditScenarioStep(scenario.currentStep, stepTrace.String(), payload, err)
	}()

	// Default to http prefix
	if !(strings.HasPrefix(strings.ToLower(urlAddress), "http://") ||
		strings.HasPrefix(strings.ToLower(urlAddress), "https://")) {
		urlAddress = "http://" + urlAddress
	}

	// Guard clause - Validate url
	if _, urlErr := url.ParseRequestURI(urlAddress); urlErr != nil {
		err = utils.ReformatError("Invalid url provided.")
		return err
	}

	// Validate input value
	var expectedHTTPResponse int
	switch result {
	case "blocked":
		expectedHTTPResponse = 403 // TODO: Confirm 403 is expected command for blocked url?
		//Previously, we were passing on anything different than 200, which I believe could lead to false positives.
		// Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
	default:
		err = utils.ReformatError("Unexpected value provided for expected command result: %s", result) // No payload is necessary if an invalid value was provided
		return err
	}

	// Create a curl command to access the supplied url and only show http response in stdout.
	cmd := "curl -s -o /dev/null -I -L -w %{http_code} " + urlAddress

	stepTrace.WriteString(fmt.Sprintf("Attempt to run command in the pod: '%s'; ", cmd))
	_, stdOut, cmdErr := conn.ExecCommand(cmd, scenario.namespace, scenario.pods[0])

	// Validate that no internal error occurred during execution of curl command
	if cmdErr != nil {
		err = utils.ReformatError("Error raised when attempting to execute curl command inside container: %v", cmdErr)
		return err
	}

	// Validate that stdout contains valid http response code
	httpResponse, parseErr := strconv.Atoi(stdOut)
	if parseErr != nil {
		err = utils.ReformatError("Unexpected result in stdout. Please ensure curl command is in the following format so that only http response code is added to standard output: '%s'", "curl -s -o /dev/null -I -L -w %%{http_code} _urlAddress_")
		return err
	}

	stepTrace.WriteString("Check expected HTTP response code was received in standard output; ")
	if httpResponse != expectedHTTPResponse {
		err = utils.ReformatError("Unexpected HTTP response code: %d", httpResponse)
	}

	payload = struct {
		Command              string
		ExpectedHTTPResponse int
		HTTPResponse         int
		StdOut               string
	}{
		Command:              cmd,
		ExpectedHTTPResponse: expectedHTTPResponse,
		HTTPResponse:         httpResponse,
		StdOut:               stdOut,
	}

	return err
}

// Name presents the name of this probe for external reference
func (probe probeStruct) Name() string {
	return "general"
}

// Path presents the path of these feature files for external reference
func (probe probeStruct) Path() string {
	return coreengine.GetFeaturePath("service_packs", "kubernetes", probe.Name())
}

// ProbeInitialize handles any overall Test Suite initialisation steps.  This is registered with the
// test handler as part of the init() function.
func (probe probeStruct) ProbeInitialize(ctx *godog.TestSuiteContext) {

	ctx.BeforeSuite(func() {
		conn = connection.Get()
	})

	ctx.AfterSuite(func() {})

}

// ScenarioInitialize provides initialization logic before each scenario is executed
func (probe probeStruct) ScenarioInitialize(ctx *godog.ScenarioContext) {

	ctx.BeforeScenario(func(s *godog.Scenario) {
		beforeScenario(&scenario, probe.Name(), s)
	})

	// Background
	ctx.Step(`^a Kubernetes cluster exists which we can deploy into$`, scenario.aKubernetesClusterIsDeployed)

	// TODO: Confirm 330
	//@CIS-5.1.3
	//ctx.Step(`^I inspect the "([^"]*)" that are configured$`, scenario.iInspectTheThatAreConfigured)
	//ctx.Step(`^I should only find wildcards in known and authorised configurations$`, scenario.iShouldOnlyFindWildcardsInKnownAndAuthorisedConfigurations)

	// TODO: Confirm 330
	//@CIS-5.6.3
	//ctx.Step(`^I attempt to create a deployment which does not have a Security Context$`, scenario.iAttemptToCreateADeploymentWhichDoesNotHaveASecurityContext)
	//ctx.Step(`^the deployment is rejected$`, scenario.theDeploymentIsRejected)

	// TODO: Confirm 331
	//ctx.Step(`^I should not be able to access the Kubernetes Web UI$`, scenario.iShouldNotBeAbleToAccessTheKubernetesWebUI)
	ctx.Step(`^the Kubernetes Web UI is disabled$`, scenario.theKubernetesWebUIIsDisabled)

	// k-gen-004
	ctx.Step(`^a pod is deployed in the cluster$`, scenario.aPodIsDeployedInTheCluster)
	ctx.Step(`^the result of a process inside the pod establishing a direct http\(s\) connection to "([^"]*)" is "([^"]*)"$`, scenario.theResultOfAProcessInsideThePodEstablishingADirectHTTPConnectionToXIsY)

	ctx.AfterScenario(func(s *godog.Scenario, err error) {
		afterScenario(scenario, probe, s, err)
	})

	ctx.BeforeStep(func(st *godog.Step) {
		scenario.currentStep = st.Text
	})

	ctx.AfterStep(func(st *godog.Step, err error) {
		scenario.currentStep = ""
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

func getKubeSystemNamespaceAndDashboardPodNamePrefixFromConfig() (kubeSystemNamespace, dashboardPodNamePrefix string) {
	kubeSystemNamespace = config.Vars.ServicePacks.Kubernetes.SystemNamespace
	dashboardPodNamePrefix = config.Vars.ServicePacks.Kubernetes.DashboardPodNamePrefix

	return
}

func (scenario *scenarioState) createPodfromObject(podObject *apiv1.Pod) (createdPodObject *apiv1.Pod, err error) {
	createdPodObject, err = conn.CreatePodFromObject(podObject, Probe.Name())
	if err == nil {
		scenario.pods = append(scenario.pods, createdPodObject.ObjectMeta.Name)
	}
	return
}

// TODO: Finish cleanup for helpers.go once #330 and #331 have been confirmed
