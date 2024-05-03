package v1alpha1

// OIDCProviderAnnotation determines which Authelia OIDC provider is used.
//
// Deprecated: the annotation key won't change but it should not have been exported here.
const OIDCProviderAnnotation = "authelia.milas.dev/oidc-provider"

// OIDCConfigFilename is the generated Authelia config filename.
//
// Deprecated: this should not have been exported here.
const OIDCConfigFilename = "authelia.oidc.yaml"

type SecretReference struct {
	Namespace string `json:"namespace,omitempty"`

	Name string `json:"name"`

	Key string `json:"key"`
}
