package autheliacfg

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	autheliav1alpha1 "github.com/milas/authelia-oidc-operator/api/v1alpha1"
)

func TestNewOIDC(t *testing.T) {
	provider := autheliav1alpha1.OIDCProvider{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "my-ns",
			Name:      "my-provider",
		},
		Spec: autheliav1alpha1.OIDCProviderSpec{
			AccessTokenLifespan:       metav1.Duration{Duration: 1 * time.Hour},
			AuthorizeCodeLifespan:     metav1.Duration{Duration: 1 * time.Minute},
			IDTokenLifespan:           metav1.Duration{Duration: 1 * time.Hour},
			RefreshTokenLifespan:      metav1.Duration{Duration: 90 * time.Minute},
			EnableClientDebugMessages: false,
			EnforcePKCE:               "public_clients_only",
			CORS: autheliav1alpha1.CORS{
				Endpoints: []string{
					"authorization",
					"token",
					"revocation",
					"introspection",
				},
				AllowedOrigins:                       []string{"https://example.com"},
				AllowedOriginsFromClientRedirectURIs: false,
			},
		},
	}

	client := autheliav1alpha1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "other-ns",
			Name:      "my-client",
		},
		Spec: autheliav1alpha1.OIDCClientSpec{
			ID:          "myapp",
			Description: "My Application",
			SecretRef: autheliav1alpha1.SecretReference{
				Name: "my-client-oidc",
				Key:  "secret",
			},
			SectorIdentifier:             "",
			Public:                       false,
			AuthorizationPolicy:          autheliav1alpha1.AuthorizationPolicyTwoFactor,
			PreconfiguredConsentDuration: metav1.Duration{},
			Audience:                     nil,
			Scopes: []autheliav1alpha1.Scope{
				"openid",
				"groups",
				"email",
				"profile",
			},
			RedirectURIs: []string{
				"https://oidc.example.com:8080/oauth2/callback",
			},
			GrantTypes: []autheliav1alpha1.GrantType{
				"refresh_token",
				"authorization_code",
			},
			ResponseTypes: []autheliav1alpha1.ResponseType{
				"code",
			},
			ResponseModes: []autheliav1alpha1.ResponseMode{
				"form_post",
				"query",
				"fragment",
			},
			UserinfoSigningAlgorithm: "none",
		},
	}

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "other-ns",
			Name:      "my-client-oidc",
		},
		Data: map[string][]byte{
			"secret": []byte("this_is_a_secret"),
		},
	}

	oidc, err := NewOIDC(
		&provider,
		[]autheliav1alpha1.OIDCClient{client},
		[]v1.Secret{secret},
	)
	require.NoError(t, err, "Failed to create OIDC config")

	cfg, err := yaml.Marshal(oidc)
	require.NoError(t, err, "Failed to marshal OIDC config as YAML")

	expected := string(loadTestData(t, "oidc.yaml"))
	actual := string(cfg)
	require.YAMLEq(t, expected, actual,
		"Marshaled config did not match expected output\n%s", expected)
}

func loadTestData(t testing.TB, path ...string) []byte {
	t.Helper()
	filePath := filepath.Join(append([]string{"testdata"}, path...)...)
	ret, err := os.ReadFile(filePath)
	require.NoError(t, err, "Failed to read testdata file")
	return ret
}
