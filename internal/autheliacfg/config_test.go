package autheliacfg

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	autheliav1alpha1 "github.com/milas/authelia-oidc-operator/api/v1alpha1"
	autheliav1alpha2 "github.com/milas/authelia-oidc-operator/api/v1alpha2"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMarshalConfig(t *testing.T) {
	fixedSaltForTests = "DETERMINISTIC_FOR_TESTS"
	t.Cleanup(func() {
		fixedSaltForTests = ""
	})

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

	client := autheliav1alpha2.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "other-ns",
			Name:      "my-client",
		},
		Spec: autheliav1alpha2.OIDCClientSpec{
			Description: "My Application",
			SecretRef: autheliav1alpha2.SecretReference{
				Name: "my-client-oidc",
				Keys: autheliav1alpha2.SecretReferenceKeys{
					ClientID:     "client_id_key",
					ClientSecret: "client_secret_key",
				},
			},
			SectorIdentifier:             "",
			Public:                       false,
			AuthorizationPolicy:          autheliav1alpha2.AuthorizationPolicyTwoFactor,
			ConsentMode:                  autheliav1alpha2.ConsentModeAuto,
			PreconfiguredConsentDuration: metav1.Duration{Duration: 1 * time.Hour},
			Audience:                     nil,
			Scopes: []autheliav1alpha2.Scope{
				"openid",
				"groups",
				"email",
				"profile",
			},
			RedirectURIs: []string{
				"https://oidc.example.com:8080/oauth2/callback",
			},
			GrantTypes: []autheliav1alpha2.GrantType{
				"refresh_token",
				"authorization_code",
			},
			ResponseTypes: []autheliav1alpha2.ResponseType{
				"code",
			},
			ResponseModes: []autheliav1alpha2.ResponseMode{
				"form_post",
				"query",
				"fragment",
			},
			UserinfoSigningAlgorithm: "none",
			TokenEndpoint: autheliav1alpha2.TokenEndpoint{
				AuthMethod: "client_secret_post",
			},
			Claims: autheliav1alpha2.OIDCClientClaims{
				Policy: &autheliav1alpha2.OIDCClaimsPolicy{
					IDToken: []string{"preferred_username"},
				},
			},
		},
	}

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "other-ns",
			Name:      "my-client-oidc",
		},
		Data: map[string][]byte{
			"client_id_key":     []byte("myapp"),
			"client_secret_key": []byte("this_is_a_secret"),
		},
	}

	oidc, err := NewOIDC(
		&provider,
		[]autheliav1alpha2.OIDCClient{client},
		[]v1.Secret{secret},
	)
	require.NoError(t, err, "Failed to create OIDC config")

	// cfg, err := yaml.Marshal(oidc)
	cfg, err := MarshalConfig(oidc)
	require.NoError(t, err, "Failed to marshal OIDC config as YAML")

	expected := string(loadTestData(t, "oidc.yaml"))
	actual := string(cfg)
	require.YAMLEq(
		t, expected, actual,
		"Marshaled config did not match expected output. Raw:\n%s", actual,
	)
}

func loadTestData(t testing.TB, path ...string) []byte {
	t.Helper()
	filePath := filepath.Join(append([]string{"testdata"}, path...)...)
	ret, err := os.ReadFile(filePath)
	require.NoError(t, err, "Failed to read testdata file")
	return ret
}
