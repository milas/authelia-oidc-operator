package v1alpha1

import (
	"github.com/milas/authelia-oidc-operator/api/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/conversion"
)

var _ conversion.Convertible = &OIDCClient{}

func (src *OIDCClient) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v1alpha2.OIDCClient)
	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()
	if dst.ObjectMeta.Annotations == nil {
		dst.ObjectMeta.Annotations = make(map[string]string)
	}
	dst.ObjectMeta.Annotations["conversion.authelia.milas.dev/oidc-client-id"] = src.Spec.ID

	secretRefClientIDKey := dst.ObjectMeta.Annotations["conversion.authelia.milas.dev/secret-ref-client-id"]
	delete(dst.ObjectMeta.Annotations, "conversion.authelia.milas.dev/secret-ref-client-id")

	dst.Spec.Description = src.Spec.Description
	dst.Spec.SecretRef = v1alpha2.SecretReference{
		Namespace: src.Spec.SecretRef.Namespace,
		Name:      src.Spec.SecretRef.Name,
		Keys: v1alpha2.SecretReferenceKeys{
			ClientID:     secretRefClientIDKey,
			ClientSecret: src.Spec.SecretRef.Key,
		},
	}
	dst.Spec.SectorIdentifier = src.Spec.SectorIdentifier
	dst.Spec.Public = src.Spec.Public
	dst.Spec.AuthorizationPolicy = v1alpha2.AuthorizationPolicy(src.Spec.AuthorizationPolicy)
	dst.Spec.Audience = src.Spec.Audience
	dst.Spec.Scopes = make([]v1alpha2.Scope, len(src.Spec.Scopes))
	for i := range src.Spec.Scopes {
		dst.Spec.Scopes[i] = v1alpha2.Scope(src.Spec.Scopes[i])
	}
	dst.Spec.RedirectURIs = src.Spec.RedirectURIs
	dst.Spec.GrantTypes = make([]v1alpha2.GrantType, len(src.Spec.GrantTypes))
	for i := range src.Spec.GrantTypes {
		dst.Spec.GrantTypes[i] = v1alpha2.GrantType(src.Spec.GrantTypes[i])
	}
	dst.Spec.ResponseTypes = make([]v1alpha2.ResponseType, len(src.Spec.ResponseTypes))
	for i := range src.Spec.ResponseTypes {
		dst.Spec.ResponseTypes[i] = v1alpha2.ResponseType(src.Spec.ResponseTypes[i])
	}
	dst.Spec.ResponseModes = make([]v1alpha2.ResponseMode, len(src.Spec.ResponseModes))
	for i := range src.Spec.ResponseModes {
		dst.Spec.ResponseModes[i] = v1alpha2.ResponseMode(src.Spec.ResponseModes[i])
	}
	dst.Spec.UserinfoSigningAlgorithm = src.Spec.UserinfoSigningAlgorithm
	return nil
}

func (dst *OIDCClient) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v1alpha2.OIDCClient)

	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()
	oidcClientID := dst.ObjectMeta.Annotations["conversion.authelia.milas.dev/oidc-client-id"]
	delete(dst.ObjectMeta.Annotations, "conversion.authelia.milas.dev/oidc-client-id")

	if src.Spec.SecretRef.Keys.ClientID != "" {
		dst.ObjectMeta.Annotations["conversion.authelia.milas.dev/secret-ref-client-id"] = src.Spec.SecretRef.Keys.ClientID
	}

	dst.Spec.ID = oidcClientID
	dst.Spec.Description = src.Spec.Description
	dst.Spec.SecretRef = SecretReference{
		Namespace: src.Spec.SecretRef.Namespace,
		Name:      src.Spec.SecretRef.Name,
		Key:       src.Spec.SecretRef.Keys.ClientSecret,
	}
	dst.Spec.SectorIdentifier = src.Spec.SectorIdentifier
	dst.Spec.Public = src.Spec.Public
	dst.Spec.AuthorizationPolicy = AuthorizationPolicy(src.Spec.AuthorizationPolicy)
	dst.Spec.Audience = src.Spec.Audience
	dst.Spec.Scopes = make([]Scope, len(src.Spec.Scopes))
	for i := range src.Spec.Scopes {
		dst.Spec.Scopes[i] = Scope(src.Spec.Scopes[i])
	}
	dst.Spec.RedirectURIs = src.Spec.RedirectURIs
	dst.Spec.GrantTypes = make([]GrantType, len(src.Spec.GrantTypes))
	for i := range src.Spec.GrantTypes {
		dst.Spec.GrantTypes[i] = GrantType(src.Spec.GrantTypes[i])
	}
	dst.Spec.ResponseTypes = make([]ResponseType, len(src.Spec.ResponseTypes))
	for i := range src.Spec.ResponseTypes {
		dst.Spec.ResponseTypes[i] = ResponseType(src.Spec.ResponseTypes[i])
	}
	dst.Spec.ResponseModes = make([]ResponseMode, len(src.Spec.ResponseModes))
	for i := range src.Spec.ResponseModes {
		dst.Spec.ResponseModes[i] = ResponseMode(src.Spec.ResponseModes[i])
	}
	dst.Spec.UserinfoSigningAlgorithm = src.Spec.UserinfoSigningAlgorithm
	return nil
}
