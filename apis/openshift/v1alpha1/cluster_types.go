/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// ClusterParameters is the configuration for a cluster spec.
type ClusterParameters struct {
	// Basic configs
	AWSAccountID              string      `json:"awsAccountID,omitempty"`
	Region                    string      `json:"region,omitempty"`
	MultiAZ                   bool        `json:"multiAZ,omitempty"`
	Version                   string      `json:"version,omitempty"`
	ChannelGroup              string      `json:"channelGroup,omitempty"`
	Expiration                metav1.Time `json:"expiration,omitempty"`
	Flavour                   string      `json:"flavour,omitempty"`
	DisableWorkloadMonitoring *bool       `json:"disableWorkloadMonitoring,omitempty"`

	// Encryption
	FIPS           bool   `json:"fips,omitempty"`
	EtcdEncryption bool   `json:"etcdEncryption,omitempty"`
	KMSKeyArn      string `json:"kmsKeyArn,omitempty"`
	// Scaling config
	ComputeMachineType string `json:"computeMachineType,omitempty"`
	ComputeNodes       int    `json:"computeNodes,omitempty"`
	Autoscaling        bool   `json:"autoscaling,omitempty"`
	MinReplicas        int    `json:"minReplicas,omitempty"`
	MaxReplicas        int    `json:"maxReplicas,omitempty"`

	// SubnetIDs
	SubnetIds []string `json:"subnetIds,omitempty"`

	// AvailabilityZones
	AvailabilityZones []string `json:"availabilityZones,omitempty"`

	// Network config
	NetworkType string `json:"networkType,omitempty"`
	MachineCIDR *IPNet `json:"machineCIDR,omitempty"`
	ServiceCIDR *IPNet `json:"serviceCIDR,omitempty"`
	PodCIDR     *IPNet `json:"podCIDR,omitempty"`
	HostPrefix  int    `json:"hostPrefix,omitempty"`
	Private     *bool  `json:"private,omitempty"`
	PrivateLink *bool  `json:"privateLink,omitempty"`

	// Properties
	CustomProperties map[string]string `json:"customProperties,omitempty"`

	// User-defined tags for AWS resources
	Tags map[string]string `json:"tags,omitempty"`

	// Simulate creating a cluster but don't actually create it
	DryRun *bool `json:"dryRun,omitempty"`

	// Disable SCP checks in the installer by setting credentials mode as mint
	DisableSCPChecks *bool `json:"disableSCPChecks,omitempty"`

	// STS
	IsSTS               bool     `json:"isSTS,omitempty"`
	RoleARN             string   `json:"roleARN,omitempty"`
	ExternalID          string   `json:"externalID,omitempty"`
	SupportRoleARN      string   `json:"supportRoleARN,omitempty"`
	OperatorIAMRoles    []string `json:"operatorIAMRoles,omitempty"`
	ControlPlaneRoleARN string   `json:"controlPlaneRoleARN,omitempty"`
	WorkerRoleARN       string   `json:"workerRoleARN,omitempty"`
	Mode                string   `json:"mode,omitempty"`

	NodeDrainGracePeriodInMinutes int `json:"nodeDrainGracePeriodInMinutes,omitempty"`

	EnableProxy               bool    `json:"enableProxy,omitempty"`
	HTTPProxy                 *string `json:"httpProxy,omitempty"`
	HTTPSProxy                *string `json:"httpsProxy,omitempty"`
	NoProxy                   *string `json:"noProxy,omitempty"`
	AdditionalTrustBundleFile *string `json:"additionalTrustBundleFile,omitempty"`
	AdditionalTrustBundle     *string `json:"additionalTrustBundle,omitempty"`

	// HyperShift options:
	Hypershift bool `json:"hypershift,omitempty"`
}

// An IPNet represents an IP network.
type IPNet struct {
	IP   string `json:"ip,omitempty"`
	Mask string `json:"mask,omitempty"`
}

// ClusterObservation are the observable fields of a Cluster.
type ClusterObservation struct {
	ClusterID    string `json:"clusterID,omitempty"`
	DNS          string `json:"dns,omitempty"`
	DetailesPage string `json:"detailesPage,omitempty"`
	UserCreated  bool   `json:"userCreated,omitempty"`
}

// A ClusterSpec defines the desired state of a Cluster.
type ClusterSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       ClusterParameters `json:"forProvider"`
}

// A ClusterStatus represents the observed state of a Cluster.
type ClusterStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          ClusterObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Cluster is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,rosa}
type Cluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterSpec   `json:"spec"`
	Status ClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterList contains a list of Cluster
type ClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Cluster `json:"items"`
}

// Cluster type metadata.
var (
	ClusterKind             = reflect.TypeOf(Cluster{}).Name()
	ClusterGroupKind        = schema.GroupKind{Group: Group, Kind: ClusterKind}.String()
	ClusterKindAPIVersion   = ClusterKind + "." + SchemeGroupVersion.String()
	ClusterGroupVersionKind = SchemeGroupVersion.WithKind(ClusterKind)
)

func init() {
	SchemeBuilder.Register(&Cluster{}, &ClusterList{})
}
