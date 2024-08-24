package autheliacfg

import (
	"fmt"

	apiv1alpha1 "github.com/milas/authelia-oidc-operator/api/v1alpha1"
	api "github.com/milas/authelia-oidc-operator/api/v1alpha2"
	"gopkg.in/yaml.v3"
	k8score "k8s.io/api/core/v1"
)

func MarshalConfig(oidc OIDC) ([]byte, error) {
	var cfg struct {
		IdentityProviders struct {
			OIDC OIDC `yaml:"oidc"`
		} `yaml:"identity_providers"`
	}
	cfg.IdentityProviders.OIDC = oidc
	return yaml.Marshal(cfg)
}

type IdentityProviders struct {
	OIDC *OIDC `yaml:"oidc,omitempty"`
}

type OIDC struct {
	// HMACSecret string `yaml:"hmac_secret"`
	//
	// IssuerPrivateKey string `yaml:"issuer_private_key"`

	AccessTokenLifespan Duration `yaml:"access_token_lifespan,omitempty"`

	AuthorizeCodeLifespan Duration `yaml:"authorize_code_lifespan,omitempty"`

	IDTokenLifespan Duration `yaml:"id_token_lifespan,omitempty"`

	RefreshTokenLifespan Duration `yaml:"refresh_token_lifespan,omitempty"`

	EnableClientDebugMessages bool `yaml:"enable_client_debug_messages,omitempty"`

	EnforcePKCE string `yaml:"enforce_pkce,omitempty"`

	CORS CORS `yaml:"cors,omitempty"`

	Clients []OIDCClient `yaml:"clients,omitempty"`
}

type CORS struct {
	Endpoints []string `yaml:"endpoints,omitempty"`

	AllowedOrigins []string `yaml:"allowed_origins,omitempty"`

	AllowedOriginsFromClientRedirectURIs bool `yaml:"allowed_origins_from_client_redirect_uris,omitempty"`
}

func (c CORS) IsZero() bool {
	return len(c.Endpoints) == 0 &&
		len(c.AllowedOrigins) == 0 &&
		!c.AllowedOriginsFromClientRedirectURIs
}

type OIDCClient struct {
	ClientID string `yaml:"client_id"`

	ClientName string `yaml:"client_name,omitempty"`

	ClientSecret string `yaml:"client_secret,omitempty"`

	SectorIdentifier string `yaml:"sector_identifier,omitempty"`

	Public bool `yaml:"public,omitempty"`

	AuthorizationPolicy string `yaml:"authorization_policy,omitempty"`

	ConsentMode string `yaml:"consent_mode,omitempty"`

	PreconfiguredConsentDuration Duration `yaml:"pre_configured_consent_duration,omitempty"`

	Audience []string `yaml:"audience,omitempty"`

	Scopes []string `yaml:"scopes,omitempty,flow"`

	RedirectURIs []string `yaml:"redirect_uris"`

	GrantTypes []string `yaml:"grant_types,omitempty,flow"`

	ResponseTypes []string `yaml:"response_types,omitempty,flow"`

	ResponseModes []string `yaml:"response_modes,omitempty,flow"`

	UserinfoSigningAlgorithm string `yaml:"userinfo_signing_algorithm,omitempty"`

	TokenEndpointAuthMethod string `yaml:"token_endpoint_auth_method,omitempty"`
}

func NewOIDC(
	provider *apiv1alpha1.OIDCProvider,
	clients []api.OIDCClient,
	secrets []k8score.Secret,
) (OIDC, error) {
	cfgClients := make([]OIDCClient, len(clients))
	for i := range clients {
		if c, err := NewOIDCClient(&clients[i], secrets); err != nil {
			return OIDC{}, err
		} else {
			cfgClients[i] = c
		}
	}

	cfgProvider := OIDC{
		AccessTokenLifespan:       Duration(provider.Spec.AccessTokenLifespan.Duration),
		AuthorizeCodeLifespan:     Duration(provider.Spec.AuthorizeCodeLifespan.Duration),
		IDTokenLifespan:           Duration(provider.Spec.IDTokenLifespan.Duration),
		RefreshTokenLifespan:      Duration(provider.Spec.RefreshTokenLifespan.Duration),
		EnableClientDebugMessages: provider.Spec.EnableClientDebugMessages,
		EnforcePKCE:               provider.Spec.EnforcePKCE,
		CORS:                      NewCORS(provider.Spec.CORS),
		Clients:                   cfgClients,
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

func NewOIDCClient(in *api.OIDCClient, secrets []k8score.Secret) (OIDCClient, error) {
	credentials, err := ResolveCredentials(*in, secrets)
	if err != nil {
		return OIDCClient{}, fmt.Errorf(
			"could not get credentials for %s/%s: %v",
			in.GetNamespace(),
			in.GetName(),
			err,
		)
	}

	c := OIDCClient{
		ClientID:                     credentials.ClientID,
		ClientName:                   in.Spec.Description,
		ClientSecret:                 credentials.ClientSecret,
		ConsentMode:                  string(in.Spec.ConsentMode),
		SectorIdentifier:             in.Spec.SectorIdentifier,
		Public:                       in.Spec.Public,
		AuthorizationPolicy:          string(in.Spec.AuthorizationPolicy),
		PreconfiguredConsentDuration: Duration(in.Spec.PreconfiguredConsentDuration.Duration),
		Audience:                     in.Spec.Audience,
		RedirectURIs:                 in.Spec.RedirectURIs,
		UserinfoSigningAlgorithm:     in.Spec.UserinfoSigningAlgorithm,
		TokenEndpointAuthMethod:      string(in.Spec.TokenEndpoint.AuthMethod),
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

	return c, nil
}
