package v1alpha2

type SecretReference struct {
	Namespace string `json:"namespace,omitempty"`

	Name string `json:"name"`

	Key string `json:"key"`
}
