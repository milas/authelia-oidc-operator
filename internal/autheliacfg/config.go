package autheliacfg

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-crypt/crypt/algorithm/pbkdf2"
	apiv1alpha1 "github.com/milas/authelia-oidc-operator/api/v1alpha1"
	api "github.com/milas/authelia-oidc-operator/api/v1alpha2"
	k8score "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const SaltAnnotation = "authelia.milas.dev/salt"

func MarshalOIDCConfig(oidc OIDC) ([]byte, error) {
	cfg := Config{
		IdentityProviders: IdentityProviders{
			OIDC: &oidc,
		},
	}
	return yaml.Marshal(cfg)
}

type Config struct {
	IdentityProviders IdentityProviders `json:"identity_providers"`
}

type IdentityProviders struct {
	OIDC *OIDC `json:"oidc,omitempty"`
}

type OIDC struct {
	// HMACSecret string `json:"hmac_secret"`
	//
	// IssuerPrivateKey string `json:"issuer_private_key"`

	AccessTokenLifespan Duration `json:"access_token_lifespan,omitempty"`

	AuthorizeCodeLifespan Duration `json:"authorize_code_lifespan,omitempty"`

	IDTokenLifespan Duration `json:"id_token_lifespan,omitempty"`

	RefreshTokenLifespan Duration `json:"refresh_token_lifespan,omitempty"`

	EnableClientDebugMessages bool `json:"enable_client_debug_messages,omitempty"`

	EnforcePKCE string `json:"enforce_pkce,omitempty"`

	ClaimsPolicies map[string]OIDCClaimsPolicy `json:"claims_policies,omitempty"`

	CORS CORS `json:"cors,omitempty"`

	Clients []OIDCClient `json:"clients,omitempty"`
}

type OIDCClaimsPolicy struct {
	IDToken []string `json:"id_token"`
}

type CORS struct {
	Endpoints []string `json:"endpoints,omitempty"`

	AllowedOrigins []string `json:"allowed_origins,omitempty"`

	AllowedOriginsFromClientRedirectURIs bool `json:"allowed_origins_from_client_redirect_uris,omitempty"`
}

func (c CORS) IsZero() bool {
	return len(c.Endpoints) == 0 &&
		len(c.AllowedOrigins) == 0 &&
		!c.AllowedOriginsFromClientRedirectURIs
}

type OIDCClient struct {
	ClientID string `json:"client_id"`

	ClientName string `json:"client_name,omitempty"`

	ClientSecret string `json:"client_secret,omitempty"`

	SectorIdentifier string `json:"sector_identifier,omitempty"`

	Public bool `json:"public,omitempty"`

	AuthorizationPolicy string `json:"authorization_policy,omitempty"`

	ConsentMode string `json:"consent_mode,omitempty"`

	PreconfiguredConsentDuration Duration `json:"pre_configured_consent_duration,omitempty"`

	Audience []string `json:"audience,omitempty"`

	Scopes []string `json:"scopes,omitempty,flow"`

	RedirectURIs []string `json:"redirect_uris"`

	GrantTypes []string `json:"grant_types,omitempty,flow"`

	ResponseTypes []string `json:"response_types,omitempty,flow"`

	ResponseModes []string `json:"response_modes,omitempty,flow"`

	UserinfoSigningAlgorithm string `json:"userinfo_signing_algorithm,omitempty"`

	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	ClaimsPolicy string `json:"claims_policy,omitempty"`
}

func NewOIDC(
	provider *apiv1alpha1.OIDCProvider,
	clients []api.OIDCClient,
	secrets []k8score.Secret,
) (OIDC, error) {
	cfgClients := make([]OIDCClient, len(clients))
	claimsPolicies := make(map[string]OIDCClaimsPolicy)
	for i := range clients {
		if c, cp, err := NewOIDCClient(&clients[i], secrets); err != nil {
			return OIDC{}, fmt.Errorf("creating client for %s/%s: %w", clients[i].GetNamespace(), clients[i].GetName(), err)
		} else {
			cfgClients[i] = c
			if cp != nil {
				claimsPolicies[c.ClaimsPolicy] = *cp
			}
		}
	}
	slices.SortFunc(cfgClients, func(a, b OIDCClient) int {
		return strings.Compare(a.ClientID, b.ClientID)
	})

	cfgProvider := OIDC{
		AccessTokenLifespan:       Duration(provider.Spec.AccessTokenLifespan.Duration),
		AuthorizeCodeLifespan:     Duration(provider.Spec.AuthorizeCodeLifespan.Duration),
		IDTokenLifespan:           Duration(provider.Spec.IDTokenLifespan.Duration),
		RefreshTokenLifespan:      Duration(provider.Spec.RefreshTokenLifespan.Duration),
		EnableClientDebugMessages: provider.Spec.EnableClientDebugMessages,
		EnforcePKCE:               provider.Spec.EnforcePKCE,
		CORS:                      NewCORS(provider.Spec.CORS),
		Clients:                   cfgClients,
		ClaimsPolicies:            claimsPolicies,
	}
	return cfgProvider, nil
}

func NewCORS(in apiv1alpha1.CORS) CORS {
	return CORS{
		Endpoints:                            in.Endpoints,
		AllowedOrigins:                       in.AllowedOrigins,
		AllowedOriginsFromClientRedirectURIs: in.AllowedOriginsFromClientRedirectURIs,
	}
}

func NewOIDCClient(in *api.OIDCClient, secrets []k8score.Secret) (OIDCClient, *OIDCClaimsPolicy, error) {
	credentials, err := ResolveCredentials(*in, secrets)
	if err != nil {
		return OIDCClient{}, nil, fmt.Errorf(
			"could not get credentials for %s/%s: %v",
			in.GetNamespace(),
			in.GetName(),
			err,
		)
	}

	var salt []byte
	if saltVal := in.ObjectMeta.Annotations[SaltAnnotation]; saltVal == "" {
		return OIDCClient{}, nil, errors.New("missing salt")
	} else {
		salt, err = base64.RawURLEncoding.DecodeString(saltVal)
		if err != nil {
			return OIDCClient{}, nil, fmt.Errorf("decoding salt: %w", err)
		}
	}

	clientSecretHash, err := hashSecret(credentials.ClientSecret, salt)
	if err != nil {
		return OIDCClient{}, nil, fmt.Errorf("hashing client secret: %w", err)
	}

	claimsPolicyName := in.Spec.Claims.PolicyName
	var inlineClaimsPolicy *OIDCClaimsPolicy
	if cp := in.Spec.Claims.Policy; cp != nil {
		claimsPolicyName = strings.Join([]string{"client", in.GetNamespace(), in.GetName()}, "_")
		inlineClaimsPolicy = claimsPolicyFromAPI(cp)
	}

	c := OIDCClient{
		ClientID:                     credentials.ClientID,
		ClientName:                   in.Spec.Description,
		ClientSecret:                 clientSecretHash,
		ConsentMode:                  string(in.Spec.ConsentMode),
		SectorIdentifier:             in.Spec.SectorIdentifier,
		Public:                       in.Spec.Public,
		AuthorizationPolicy:          string(in.Spec.AuthorizationPolicy),
		PreconfiguredConsentDuration: Duration(in.Spec.PreconfiguredConsentDuration.Duration),
		Audience:                     in.Spec.Audience,
		RedirectURIs:                 in.Spec.RedirectURIs,
		UserinfoSigningAlgorithm:     in.Spec.UserinfoSigningAlgorithm,
		TokenEndpointAuthMethod:      string(in.Spec.TokenEndpoint.AuthMethod),
		ClaimsPolicy:                 claimsPolicyName,
	}

	c.Scopes = make([]string, len(in.Spec.Scopes))
	for i := range in.Spec.Scopes {
		c.Scopes[i] = string(in.Spec.Scopes[i])
	}

	c.GrantTypes = make([]string, len(in.Spec.GrantTypes))
	for i := range in.Spec.GrantTypes {
		c.GrantTypes[i] = string(in.Spec.GrantTypes[i])
	}

	c.ResponseTypes = make([]string, len(in.Spec.ResponseTypes))
	for i := range in.Spec.ResponseTypes {
		c.ResponseTypes[i] = string(in.Spec.ResponseTypes[i])
	}

	c.ResponseModes = make([]string, len(in.Spec.ResponseModes))
	for i := range in.Spec.ResponseModes {
		c.ResponseModes[i] = string(in.Spec.ResponseModes[i])
	}

	return c, inlineClaimsPolicy, nil
}

func claimsPolicyFromAPI(claims *api.OIDCClaimsPolicy) *OIDCClaimsPolicy {
	ret := &OIDCClaimsPolicy{
		IDToken: slices.Clone(claims.IDToken),
	}
	return ret
}

func hashSecret(v string, salt []byte) (string, error) {
	hash, err := pbkdf2.New()
	if err != nil {
		return "", err
	}
	digest, err := hash.HashWithSalt(v, salt)
	if err != nil {
		return "", err
	}
	return digest.String(), nil
}
