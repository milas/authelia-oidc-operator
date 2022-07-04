package v1alpha1

const OIDCProviderAnnotation = "authelia.milas.dev/oidc-provider"

const OIDCConfigFilename = "authelia.oidc.yaml"

type SecretReference struct {
	Namespace string `json:"namespace,omitempty"`

	Name string `json:"name"`

	Key string `json:"key"`
}
