@k-gen
@probes/kubernetes/general
Feature: General Cluster Security Configurations
    As a Security Auditor
    I want to ensure that Kubernetes clusters have general security configurations in place
    So that no general cluster vulnerabilities can be exploited

    Background:
        Given a Kubernetes cluster exists which we can deploy into

    # Disabling until #330 is discussed
    # @k-gen-001
    # Scenario Outline: Minimise wildcards in Roles and Cluster Roles
    #     When I inspect the "<rolelevel>" that are configured
    #     Then I should only find wildcards in known and authorised configurations

    #     Examples:
    #         | rolelevel     |
    #         | Roles         |
    #         | Cluster Roles |

    # Disabling until #330 is confirmed
    # @k-gen-002
    # Scenario: Ensure Security Contexts are enforced
    #     When I attempt to create a deployment which does not have a Security Context
    #     Then the deployment is rejected

    # Disabling until #331 is confirmed
    # @k-gen-003
    # Scenario: Ensure Kubernetes Web UI is disabled
    #     And the Kubernetes Web UI is disabled
    #     Then I should not be able to access the Kubernetes Web UI

    # Confirm #331
    @k-gen-003
    Scenario: Ensure Kubernetes Web UI is disabled 
        The Kubernetes Web UI (Dashboard) has been a historical source of vulnerability and should only be deployed when necessary. 
        Then the Kubernetes Web UI is disabled

    @k-gen-004
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