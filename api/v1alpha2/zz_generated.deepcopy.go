//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2022 Milas Bowman

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

package v1alpha2

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCClient) DeepCopyInto(out *OIDCClient) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCClient.
func (in *OIDCClient) DeepCopy() *OIDCClient {
	if in == nil {
		return nil
	}
	out := new(OIDCClient)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OIDCClient) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCClientList) DeepCopyInto(out *OIDCClientList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]OIDCClient, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCClientList.
func (in *OIDCClientList) DeepCopy() *OIDCClientList {
	if in == nil {
		return nil
	}
	out := new(OIDCClientList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OIDCClientList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCClientSpec) DeepCopyInto(out *OIDCClientSpec) {
	*out = *in
	out.SecretRef = in.SecretRef
	out.PreconfiguredConsentDuration = in.PreconfiguredConsentDuration
	if in.Audience != nil {
		in, out := &in.Audience, &out.Audience
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Scopes != nil {
		in, out := &in.Scopes, &out.Scopes
		*out = make([]Scope, len(*in))
		copy(*out, *in)
	}
	if in.RedirectURIs != nil {
		in, out := &in.RedirectURIs, &out.RedirectURIs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.GrantTypes != nil {
		in, out := &in.GrantTypes, &out.GrantTypes
		*out = make([]GrantType, len(*in))
		copy(*out, *in)
	}
	if in.ResponseTypes != nil {
		in, out := &in.ResponseTypes, &out.ResponseTypes
		*out = make([]ResponseType, len(*in))
		copy(*out, *in)
	}
	if in.ResponseModes != nil {
		in, out := &in.ResponseModes, &out.ResponseModes
		*out = make([]ResponseMode, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCClientSpec.
func (in *OIDCClientSpec) DeepCopy() *OIDCClientSpec {
	if in == nil {
		return nil
	}
	out := new(OIDCClientSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCClientStatus) DeepCopyInto(out *OIDCClientStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCClientStatus.
func (in *OIDCClientStatus) DeepCopy() *OIDCClientStatus {
	if in == nil {
		return nil
	}
	out := new(OIDCClientStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretReference) DeepCopyInto(out *SecretReference) {
	*out = *in
	out.Keys = in.Keys
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretReference.
func (in *SecretReference) DeepCopy() *SecretReference {
	if in == nil {
		return nil
	}
	out := new(SecretReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretReferenceKeys) DeepCopyInto(out *SecretReferenceKeys) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretReferenceKeys.
func (in *SecretReferenceKeys) DeepCopy() *SecretReferenceKeys {
	if in == nil {
		return nil
	}
	out := new(SecretReferenceKeys)
	in.DeepCopyInto(out)
	return out
}
