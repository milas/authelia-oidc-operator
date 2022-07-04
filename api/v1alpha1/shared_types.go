package v1alpha1

const OidcProviderAnnotation = "authelia.milas.dev/oidc_provider"

const OidcConfigFilename = "authelia.oidc.yaml"

type SecretReference struct {
	Namespace string `json:"namespace,omitempty"`

	Name string `json:"name"`

	Key string `json:"key"`
}
