package v1alpha2

type SecretReference struct {
	Namespace string `json:"namespace,omitempty"`

	Name string `json:"name"`

	Keys SecretReferenceKeys `json:"fields,omitempty"`
}

type SecretReferenceKeys struct {
	ClientID string `json:"client_id,omitempty"`

	ClientSecret string `json:"client_secret,omitempty"`
}

type OIDCClaimsPolicy struct {
	// +optional
	IDToken []string `json:"id_token,omitempty"`
}
