package autheliacfg

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	autheliav1alpha1 "github.com/milas/authelia-oidc-operator/api/v1alpha1"
)

func SecretRefToValue(obj client.Object, ref autheliav1alpha1.SecretReference, secrets []v1.Secret) ([]byte, error) {
	targetNs := ref.Namespace
	if targetNs == "" {
		targetNs = obj.GetNamespace()
	}

	for i := range secrets {
		if secrets[i].Namespace != targetNs || secrets[i].Name != ref.Name {
			continue
		}
		v, ok := secrets[i].Data[ref.Key]
		if !ok {
			return nil, fmt.Errorf("secret %s/%s does not contain %s key",
				secrets[i].Namespace, secrets[i].Name, ref.Key)
		}
		return v, nil
	}
	return nil, fmt.Errorf("secret %s/%s does not exist", targetNs, ref.Name)
}

func SecretRefToStringValue(obj client.Object, ref autheliav1alpha1.SecretReference,
	secrets []v1.Secret) (string, error) {
	v, err := SecretRefToValue(obj, ref, secrets)
	if err != nil {
		return "", err
	}
	return string(v), nil
}
