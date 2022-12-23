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

package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OIDCClientSpec defines the desired state of OIDCClient
type OIDCClientSpec struct {
	// Description is a friendly name shown for the client in the UI.
	//
	// +optional
	Description string `json:"description,omitempty"`

	// SecretRef refers to a Kubernetes v1.Secret that contains the shared
	// secret between Authelia and the application consuming this client in
	// the specified key.
	//
	// +optional
	SecretRef SecretReference `json:"secret_ref,omitempty"`

	SectorIdentifier string `json:"sector_identifier,omitempty"`

	// Public enables the public client type for this client.
	//
	// +optional
	Public bool `json:"public"`

	// AuthorizationPolicy for the client.
	//
	// +optional
	AuthorizationPolicy AuthorizationPolicy `json:"authorization_policy,omitempty"`

	PreconfiguredConsentDuration metav1.Duration `json:"preconfigured_consent_duration,omitempty"`

	Audience []string `json:"audience,omitempty"`

	// Scopes to allow the client to consume.
	//
	// See: https://www.authelia.com/integration/openid-connect/introduction/#scope-definitions
	//
	// +optional
	Scopes []Scope `json:"scopes,omitempty"`

	// RedirectURIs to permit client callbacks to.
	//
	// +kubebuilder:validation:MinItems=1
	RedirectURIs []string `json:"redirect_uris"`

	// GrantTypes this client can return.
	//
	// It is recommended that this isn’t configured at this time unless you
	// know what you’re doing.
	//
	// +optional
	GrantTypes []GrantType `json:"grant_types,omitempty"`

	// ResponseTypes this client can return.
	//
	// It is recommended that this isn’t configured at this time unless you
	// know what you’re doing.
	//
	// +optional
	ResponseTypes []ResponseType `json:"response_types,omitempty"`

	// ResponseModes this client can return.
	//
	// It is recommended that this isn’t configured at this time unless you
	// know what you’re doing.
	//
	// +optional
	ResponseModes []ResponseMode `json:"response_modes,omitempty"`

	// UserinfoSigningAlgorithm is the algorithm used to sign the userinfo endpoint responses.
	//
	// +kubebuilder:validation:Enum=none;RS256
	UserinfoSigningAlgorithm string `json:"userinfo_signing_algorithm,omitempty"`
}

// AuthorizationPolicy for a client.
//
// +kubebuilder:validation:Enum=one_factor;two_factor
type AuthorizationPolicy string

const (
	AuthorizationPolicyOneFactor AuthorizationPolicy = "one_factor"
	AuthorizationPolicyTwoFactor AuthorizationPolicy = "two_factor"
)

// OIDCClientStatus defines the observed state of OIDCClient
type OIDCClientStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// OIDCClient is the Schema for the oidcclients API
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Description",type=string,JSONPath=`.spec.description`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type OIDCClient struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OIDCClientSpec   `json:"spec,omitempty"`
	Status OIDCClientStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OIDCClientList contains a list of OIDCClient
type OIDCClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OIDCClient `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OIDCClient{}, &OIDCClientList{})
}

// +kubebuilder:validation:Enum=openid;offline_access;groups;email;profile

type Scope string

// +kubebuilder:validation:Enum=implicit;refresh_token;authorization_code;password;client_credentials

type GrantType string

// +kubebuilder:validation:Enum=code;"code id_token";id_token;"token id_token";token;"token id_token code"

type ResponseType string

// +kubebuilder:validation:Enum=form_post;query;fragment

type ResponseMode string
