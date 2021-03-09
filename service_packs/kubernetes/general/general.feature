@k-gen
@probes/kubernetes/general
Feature: General Cluster Security Configurations
    As a Security Auditor
    I want to ensure that Kubernetes clusters have general security configurations in place
    So that no general cluster vulnerabilities can be exploited

    Background:
        Given a Kubernetes cluster exists which we can deploy into

    @k-gen-001
    Scenario: Ensure Kubernetes Web UI is disabled 
        The Kubernetes Web UI (Dashboard) has been a historical source of vulnerability and should only be deployed when necessary. 
        
        Then the Kubernetes Web UI is disabled

    @k-gen-002
    Scenario Outline: Test outgoing connectivity of a deployed pod
        Ensure that containers running inside Kubernetes clusters cannot directly access the Internet
        So that Internet traffic can be inspected and controlled

        When a pod is deployed in the cluster
        Then the result of a process inside the pod establishing a direct http(s) connection to "<URL>" is "<RESULT>"
        
        # If URL doesn't contain http(s) prefix, 'http' will be used by default
        Examples:
            | URL               | RESULT  |
            | www.google.com    | blocked |
            | www.microsoft.com | blocked |
            | www.ubuntu.com    | blocked |