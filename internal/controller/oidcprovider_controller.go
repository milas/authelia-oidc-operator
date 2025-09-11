/*
Copyright 2022 Milas Bowman

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/milas/authelia-oidc-operator/api/v1alpha1"
	"github.com/milas/authelia-oidc-operator/api/v1alpha2"
	"github.com/milas/authelia-oidc-operator/internal/autheliacfg"
	"golang.org/x/sync/errgroup"
	k8score "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"
)

const OIDCProviderAnnotation = "authelia.milas.dev/oidc-provider"

const OIDCConfigFilename = "authelia.oidc.yaml"

// OIDCProviderReconciler reconciles a OIDCProvider object
type OIDCProviderReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	defaultOIDCProvider *client.ObjectKey
}

// +kubebuilder:rbac:groups=authelia.milas.dev,resources=oidcproviders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=authelia.milas.dev,resources=oidcproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authelia.milas.dev,resources=oidcproviders/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the OIDCProvider object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *OIDCProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var provider v1alpha1.OIDCProvider
	if err := r.Client.Get(ctx, req.NamespacedName, &provider); err != nil {
		if k8serr.IsNotFound(err) {
			// TODO(milas): tear down secret
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// TODO(milas): ingress-nginx sets up a special lister to handle "indexing"
	// 	by annotation - listing across all namespaces is not great
	var oidcClientList v1alpha2.OIDCClientList
	if err := r.Client.List(ctx, &oidcClientList); err != nil {
		return ctrl.Result{}, err
	}

	for _, oidcClient := range oidcClientList.Items {
		saltVal := oidcClient.ObjectMeta.Annotations[autheliacfg.SaltAnnotation]
		if saltVal == "" {
			salt, err := randBytes(algorithm.SaltLengthDefault)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("generating salt for %s: %w", req.NamespacedName, err)
			}
			saltVal = base64.RawURLEncoding.EncodeToString(salt)
			oidcClient.ObjectMeta.Annotations[autheliacfg.SaltAnnotation] = saltVal

			if err := r.Client.Update(ctx, &oidcClient); err != nil {
				return ctrl.Result{}, fmt.Errorf("updating %s: %w", req.NamespacedName, err)
			}
		}
	}

	secrets, err := r.fetchSecrets(ctx, &provider, oidcClientList.Items)
	if err != nil {
		// TODO(milas): update status
		return ctrl.Result{}, fmt.Errorf("failed to fetch secrets for %s: %v", req.NamespacedName, err)
	}

	oidcCfg, err := autheliacfg.NewOIDC(&provider, oidcClientList.Items, secrets)
	if err != nil {
		// TODO(milas): update status
		return ctrl.Result{}, fmt.Errorf("failed to create oidc config for %s: %v", req.NamespacedName, err)
	}

	cfgYAML, err := autheliacfg.MarshalOIDCConfig(oidcCfg)
	if err != nil {
		// TODO(milas): update status
		return ctrl.Result{}, fmt.Errorf("failed to marshal oidc yaml for %s: %v", req.NamespacedName, err)
	}

	cfgSecretKey := client.ObjectKey{Namespace: req.Namespace, Name: fmt.Sprintf("%s-oidc", req.Name)}
	var retSecret k8score.Secret
	if err := r.Client.Get(ctx, cfgSecretKey, &retSecret); err != nil {
		if !k8serr.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		retSecret = k8score.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: cfgSecretKey.Namespace,
				Name:      cfgSecretKey.Name,
			},
			Data: map[string][]byte{
				OIDCConfigFilename: cfgYAML,
			},
		}
		if err := controllerutil.SetControllerReference(&provider, &retSecret, r.Scheme); err != nil {
			return ctrl.Result{}, nil
		}
		if err := r.Client.Create(ctx, &retSecret); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create secret for %s: %v", req.NamespacedName, err)
		}

		return ctrl.Result{}, nil
	}

	var existingCfg autheliacfg.Config
	if err := yaml.Unmarshal(retSecret.Data[OIDCConfigFilename], &existingCfg); err != nil {
		logger.Error(err, "failed to unmarshal existing config")
	} else {
		diff := cmp.Diff(*existingCfg.IdentityProviders.OIDC, oidcCfg, cmpopts.EquateEmpty())
		if diff == "" {
			return ctrl.Result{}, nil
		}
		logger.Info("drift detected", "diff", diff)
	}

	retSecret.Data[OIDCConfigFilename] = cfgYAML
	if err := r.Client.Update(ctx, &retSecret); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update secret for %s: %v", req.NamespacedName, err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OIDCProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	secretNameExtractFunc := func(obj client.Object) []string {
		return []string{obj.GetName()}
	}
	if err := mgr.GetFieldIndexer().IndexField(
		context.TODO(), &k8score.Secret{}, metav1.ObjectNameField,
		secretNameExtractFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for Secret on field %s: %v", metav1.ObjectNameField, err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OIDCProvider{}).
		Owns(&k8score.Secret{}).
		Watches(
			&v1alpha2.OIDCClient{},
			handler.EnqueueRequestsFromMapFunc(
				func(_ context.Context, object client.Object) []reconcile.Request {
					providerKey := r.providerForClient(object)
					if providerKey == nil {
						return nil
					}
					return []reconcile.Request{{NamespacedName: *providerKey}}
				},
			),
		).
		Complete(r)
}

func (r *OIDCProviderReconciler) providerForClient(obj client.Object) *client.ObjectKey {
	provider := obj.GetAnnotations()[OIDCProviderAnnotation]
	if provider == "" {
		return r.defaultOIDCProvider
	}

	var namespace, name string
	parts := strings.SplitN(provider, "/", 2)
	if len(parts) == 1 {
		namespace = obj.GetNamespace()
		name = parts[0]
	} else {
		namespace = parts[0]
		name = parts[1]
	}

	return &client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
}

func (r *OIDCProviderReconciler) fetchSecrets(
	ctx context.Context,
	_ *v1alpha1.OIDCProvider,
	clients []v1alpha2.OIDCClient,
) ([]k8score.Secret, error) {
	var eg errgroup.Group
	secrets := make([]k8score.Secret, len(clients))
	for i, c := range clients {
		i := i
		secretKey := client.ObjectKey{
			Namespace: namespaceForSecretRef(&c, c.Spec.SecretRef),
			Name:      c.Spec.SecretRef.Name,
		}
		eg.Go(
			func() error {
				if err := r.Client.Get(ctx, secretKey, &secrets[i]); err != nil {
					return err
				}
				return nil
			},
		)
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return secrets, nil
}

func namespaceForSecretRef(obj client.Object, ref v1alpha2.SecretReference) string {
	if ref.Namespace != "" {
		return ref.Namespace
	}
	return obj.GetNamespace()
}

// randBytes returns random arbitrary bytes with a length of n.
//
// from x/crypto/internal
func randBytes(n int) (bytes []byte, err error) {
	bytes = make([]byte, n)

	if _, err = io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, err
	}

	return bytes, nil
}
