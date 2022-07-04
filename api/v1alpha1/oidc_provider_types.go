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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OIDCProviderSpec defines the desired state of OIDCProvider
type OIDCProviderSpec struct {
	// +optional
	HmacSecretRef SecretReference `json:"hmac_secret_ref"`

	// +optional
	IssuerPrivateKeyRef SecretReference `json:"issuer_private_key_ref"`

	AccessTokenLifespan metav1.Duration `json:"access_token_lifespan,omitempty"`

	AuthorizeCodeLifespan metav1.Duration `json:"authorize_code_lifespan,omitempty"`

	IDTokenLifespan metav1.Duration `json:"id_token_lifespan,omitempty"`

	RefreshTokenLifespan metav1.Duration `json:"refresh_token_lifespan,omitempty"`

	EnableClientDebugMessages bool `json:"enable_client_debug_messages,omitempty"`

	// EnforcePKCE sets the Proof Key for Code Exchange enforcement policy.
	//
	// +kubebuilder:validation:Enum=never;public_clients_only;always
	// +optional
	EnforcePKCE string `json:"enforce_pkce,omitempty"`

	CORS CORS `json:"cors,omitempty"`
}

type CORS struct {
	// Endpoints to configure with cross-origin resource sharing headers.
	//
	// It is recommended that the userinfo option is at least in this list.
	//
	// +kubebuilder:validation:Enum=authorization;token;revocation;introspection;userinfo
	// +optional
	Endpoints []string `json:"endpoints,omitempty"`

	AllowedOrigins []string `json:"allowed_origins,omitempty"`

	AllowedOriginsFromClientRedirectURIs bool `json:"allowed_origins_from_client_redirect_uris,omitempty"`
}

// OIDCProviderStatus defines the observed state of OIDCProvider
type OIDCProviderStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// OIDCProvider is the Schema for the oidcproviders API
type OIDCProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OIDCProviderSpec   `json:"spec,omitempty"`
	Status OIDCProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OIDCProviderList contains a list of OIDCProvider
type OIDCProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OIDCProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OIDCProvider{}, &OIDCProviderList{})
}
