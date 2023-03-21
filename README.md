# OPA-policies-for-EKS-cluster

OPA policies for hardening EKS cluster
Here are some OPA policies that can be used to harden an EKS cluster:
1.	Ensure that all EKS worker nodes are running the latest recommended Amazon EKS-optimized Amazon Machine Image (AMI):

package eks.hardening

import data.aws.ec2

latest_ami := "ami-0c2f20f168de4de4d"  # Replace with the latest recommended AMI ID

default allow = false

ami_id[node_id] {
    node := aws.ec2.instances[_]
    node.iam_instance_profile.roles[_] == "worker"
    node.image_id != latest_ami
    node_id := node.instance_id
}

2.	Ensure that all worker nodes have the required minimum set of EC2 instance tags:

package eks.hardening

import data.aws.ec2

required_tags := {
    "KubernetesCluster": "my-cluster",
    "Environment": "prod",
}

default allow = false

tag_exists[node_id] {
    node := aws.ec2.instances[_]
    node.iam_instance_profile.roles[_] == "worker"
    all(tag_key, tag_value := required_tags) {
        node.tags[tag_key] == tag_value
    }
    node_id := node.instance_id
}

3.	Ensure that all worker nodes have the required security group rules:

package eks.hardening

import data.aws.ec2

required_ingress_rules := {
    "tcp": [
        {
            "from_port": 22,
            "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"]
        }
    ],
    "udp": []
}

default allow = false

ingress_rule_exists[node_id, protocol, from_port, to_port, cidr_block] {
    node := aws.ec2.instances[_]
    node.iam_instance_profile.roles[_] == "worker"
    node.security_groups[_].ip_permissions[_].ip_protocol == protocol
    node.security_groups[_].ip_permissions[_].from_port == from_port
    node.security_groups[_].ip_permissions[_].to_port == to_port
    some(cidr_block := required_ingress_rules[protocol][_].cidr_blocks[_]) {
        node.security_groups[_].ip_permissions[_].ip_ranges[_].cidr_ip == cidr_block
    }
    node_id := node.instance_id
}

4.	Ensure that the Kubernetes API server is accessible only from known IP addresses:

package eks.hardening

import data.kubernetes

default allow = false

allowed_ips := ["10.0.0.0/8", "192.168.0.0/16"]  # Replace with your own list of allowed IP addresses

ip_allowed {
    request := kubernetes.admission.request.object.metadata
    all(ip := allowed_ips) {
        net.cidr_contains(ip, request.annotations["eks.amazonaws.com/ingress-access"])
    }
}

5.	Ensure that RBAC policies are correctly configured:

package eks.hardening

import data.kubernetes

default allow = false

api_groups := ["", "apps", "extensions", "batch", "networking.k8s.io"]

allow {
    rule := kubernetes.admission.request.object.spec.template.spec.containers[_].securityContext.privileged
    rule == false
}

allow {
    rule := kubernetes.admission.request.object.spec.template.spec.initContainers[_].securityContext.privileged
    rule == false
}

allow {
    rule := kubernetes.admission.request.object.spec.template.spec.securityContext.seLinuxOptions.type == "spc_t"
    rule == true
}

allow {
    rule := kubernetes.admission.request.object.kind
