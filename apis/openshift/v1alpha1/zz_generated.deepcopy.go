//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2020 The Crossplane Authors.

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Cluster) DeepCopyInto(out *Cluster) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Cluster.
func (in *Cluster) DeepCopy() *Cluster {
	if in == nil {
		return nil
	}
	out := new(Cluster)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Cluster) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterList) DeepCopyInto(out *ClusterList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Cluster, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterList.
func (in *ClusterList) DeepCopy() *ClusterList {
	if in == nil {
		return nil
	}
	out := new(ClusterList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterObservation) DeepCopyInto(out *ClusterObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterObservation.
func (in *ClusterObservation) DeepCopy() *ClusterObservation {
	if in == nil {
		return nil
	}
	out := new(ClusterObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterParameters) DeepCopyInto(out *ClusterParameters) {
	*out = *in
	in.Expiration.DeepCopyInto(&out.Expiration)
	if in.DisableWorkloadMonitoring != nil {
		in, out := &in.DisableWorkloadMonitoring, &out.DisableWorkloadMonitoring
		*out = new(bool)
		**out = **in
	}
	if in.SubnetIds != nil {
		in, out := &in.SubnetIds, &out.SubnetIds
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AvailabilityZones != nil {
		in, out := &in.AvailabilityZones, &out.AvailabilityZones
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.MachineCIDR != nil {
		in, out := &in.MachineCIDR, &out.MachineCIDR
		*out = new(IPNet)
		**out = **in
	}
	if in.ServiceCIDR != nil {
		in, out := &in.ServiceCIDR, &out.ServiceCIDR
		*out = new(IPNet)
		**out = **in
	}
	if in.PodCIDR != nil {
		in, out := &in.PodCIDR, &out.PodCIDR
		*out = new(IPNet)
		**out = **in
	}
	if in.Private != nil {
		in, out := &in.Private, &out.Private
		*out = new(bool)
		**out = **in
	}
	if in.PrivateLink != nil {
		in, out := &in.PrivateLink, &out.PrivateLink
		*out = new(bool)
		**out = **in
	}
	if in.CustomProperties != nil {
		in, out := &in.CustomProperties, &out.CustomProperties
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.DryRun != nil {
		in, out := &in.DryRun, &out.DryRun
		*out = new(bool)
		**out = **in
	}
	if in.DisableSCPChecks != nil {
		in, out := &in.DisableSCPChecks, &out.DisableSCPChecks
		*out = new(bool)
		**out = **in
	}
	if in.OperatorIAMRoles != nil {
		in, out := &in.OperatorIAMRoles, &out.OperatorIAMRoles
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.HTTPProxy != nil {
		in, out := &in.HTTPProxy, &out.HTTPProxy
		*out = new(string)
		**out = **in
	}
	if in.HTTPSProxy != nil {
		in, out := &in.HTTPSProxy, &out.HTTPSProxy
		*out = new(string)
		**out = **in
	}
	if in.NoProxy != nil {
		in, out := &in.NoProxy, &out.NoProxy
		*out = new(string)
		**out = **in
	}
	if in.AdditionalTrustBundleFile != nil {
		in, out := &in.AdditionalTrustBundleFile, &out.AdditionalTrustBundleFile
		*out = new(string)
		**out = **in
	}
	if in.AdditionalTrustBundle != nil {
		in, out := &in.AdditionalTrustBundle, &out.AdditionalTrustBundle
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterParameters.
func (in *ClusterParameters) DeepCopy() *ClusterParameters {
	if in == nil {
		return nil
	}
	out := new(ClusterParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterSpec) DeepCopyInto(out *ClusterSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterSpec.
func (in *ClusterSpec) DeepCopy() *ClusterSpec {
	if in == nil {
		return nil
	}
	out := new(ClusterSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterStatus) DeepCopyInto(out *ClusterStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	out.AtProvider = in.AtProvider
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterStatus.
func (in *ClusterStatus) DeepCopy() *ClusterStatus {
	if in == nil {
		return nil
	}
	out := new(ClusterStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPNet) DeepCopyInto(out *IPNet) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPNet.
func (in *IPNet) DeepCopy() *IPNet {
	if in == nil {
		return nil
	}
	out := new(IPNet)
	in.DeepCopyInto(out)
	return out
}
