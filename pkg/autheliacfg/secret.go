package autheliacfg

import (
	"fmt"
	autheliav1alpha2 "github.com/milas/authelia-oidc-operator/api/v1alpha2"

	v1 "k8s.io/api/core/v1"
)

type OIDCCredentials struct {
	ClientID     string
	ClientSecret string
}

func ResolveCredentials(
	client autheliav1alpha2.OIDCClient,
	secrets []v1.Secret,
) (OIDCCredentials, error) {
	ref := *client.Spec.SecretRef.DeepCopy()
	if ref.Namespace == "" {
		ref.Namespace = client.GetNamespace()
	}

	clientID := client.ObjectMeta.Annotations["conversion.authelia.milas.dev/oidc-client-id"]
	if clientID == "" {
		clientIDKey := ref.Keys.ClientID
		if clientIDKey == "" {
			clientIDKey = "client_id"
		}
		var err error
		clientID, err = SecretRefToStringValue(ref.Namespace, ref.Name, clientIDKey, secrets)
		if err != nil {
			return OIDCCredentials{}, err
		}
	}

	clientSecretKey := ref.Keys.ClientSecret
	if clientSecretKey == "" {
		clientSecretKey = "client_secret"
	}
	clientSecret, err := SecretRefToStringValue(ref.Namespace, ref.Name, clientSecretKey, secrets)
	if err != nil {
		return OIDCCredentials{}, err
	}

	return OIDCCredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, nil
}

func SecretRefToValue(
	namespace string,
	name string,
	key string,
	secrets []v1.Secret,
) ([]byte, error) {
	for i := range secrets {
		if secrets[i].Namespace != namespace || secrets[i].Name != name {
			continue
		}
		v, ok := secrets[i].Data[key]
		if !ok {
			return nil, fmt.Errorf("secret %s/%s does not contain %s key",
				secrets[i].Namespace, secrets[i].Name, key)
		}
		return v, nil
	}
	return nil, fmt.Errorf("secret %s/%s does not exist", namespace, name)
}

func SecretRefToStringValue(
	namespace string,
	name string,
	key string,
	secrets []v1.Secret,
) (string, error) {
	v, err := SecretRefToValue(namespace, name, key, secrets)
	if err != nil {
		return "", err
	}
	return string(v), nil
}
