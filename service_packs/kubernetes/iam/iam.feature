@k-iam
@probes/kubernetes/iam
Feature: Ensure stringent authentication and authorisation
    As a Security Auditor
    I want to ensure that stringent authentication and authorisation policies are applied to my organisation's Kubernetes clusters
    So that only approved actors have the ability to perform sensitive operations in order to prevent malicious attacks on my organization

    Background:
        Given a Kubernetes cluster exists which we can deploy into

    @k-iam-001
    Scenario Outline: Prevent cross namespace Azure Identities

        Security Standard References:
            - AZ-AAD-AI-1.0

        Given an AzureIdentityBinding called "probr-aib" exists in the namespace called "default"
        Then I succeed to create a simple pod in "<NAMESPACE>" namespace assigned with the "probr-aib" AzureIdentityBinding
        #But an attempt to obtain an access token from that pod should "<RESULT>"

        Examples:
			| NAMESPACE     | RESULT  |
			| the probr     | Fail    |
			| the default   | Succeed |

    @k-iam-002
    Scenario: Prevent cross namespace Azure Identity Bindings

        Security Standard References:
            - AZ-AAD-AI-1.1

        And the namespace called "default" has an AzureIdentity called "probr-probe"
        When I create an AzureIdentityBinding called "probr-aib" in the Probr namespace bound to the "probr-probe" AzureIdentity
        And I deploy a pod assigned with the "probr-aib" AzureIdentityBinding into the Probr namespace
        Then the pod is deployed successfully
        But an attempt to obtain an access token from that pod should fail

    @k-iam-003
    Scenario: Prevent access to AKS credentials via Azure Identity Components

        Security Standard References:
            - AZ-AAD-AI-1.2

        And the cluster has managed identity components deployed
        When I execute the command "cat /etc/kubernetes/azure.json" against the MIC pod
        Then Kubernetes should prevent me from running the command
