# authelia-oidc-operator
Manage [OIDC]() clients for [Authelia](https://www.authelia.com/) SSO using Kubernetes CRDs.

## Status
⚠ **ALPHA** - APIs may change and test coverage is limited!

- [x] `OIDCProvider` CRD
- [x] `OIDCClient` CRD
- [ ] Helm chart
- [ ] Status updates on CRDs

## Compatibility
* Authelia 4.39.x (other versions might work)

## Description
Managing OIDC clients for Authelia in a Kubernetes cluster requires centralizing
the config with (excellent!) default Helm chart.

The `authelia-oidc-operator` makes it possible to create & manage OIDC clients
using CRDs, which can live in the app namespace.

## Getting Started

> ℹ️ There's currently no Helm chart available!
>
> This is using the default kubebuilder deployment setup currently.
> Manual intervention _will_ be required to migrate to a Helm-based install in the future.

1. Install CRDs
    ```sh
    kubectl apply \
      -f https://raw.githubusercontent.com/milas/authelia-oidc-operator/main/config/crd/bases/authelia.milas.dev_oidcproviders.yaml \
      -f https://raw.githubusercontent.com/milas/authelia-oidc-operator/main/config/crd/bases/authelia.milas.dev_oidcclients.yaml
    ```

2. Deploy the controller to the cluster:
    ```sh
    IMG="ghcr.io/milas/authelia-oidc-operator:latest" make deploy
    ```

3. Create an `OIDCProvider`:

   **`oidc_provider.yaml`**
    ```yaml
    apiVersion: authelia.milas.dev/v1alpha1
    kind: OIDCProvider
    metadata:
      name: default
      namespace: authelia
    spec:
      refresh_token_lifespan: '30d'
      cors:
        allowed_origins:
          - 'https://example.com'
    ```
    ```sh
    kubectl apply -f ./oidc_provider.yaml
    ```
4. Create an `OIDCClient`:

   **`oidc_client.yaml`**
    ```yaml
    apiVersion: authelia.milas.dev/v1alpha2
    kind: OIDCClient
    metadata:
      name: my-client
      namespace: my-app
      annotations:
        authelia.milas.dev/oidc-provider: authelia/default
    spec:
      description: My Application
      secret_ref:
        name: 'my-app'
        fields:
          client_id: 'OIDC_CLIENT_ID'
          client_secret: 'OIDC_CLIENT_SECRET'
      public: false
      authorization_policy: two_factor
      consent_mode: implicit
      token_endpoint:
        auth_method: client_secret_post
      redirect_uris:
        - 'https://example.com:8080/oauth2/callback'
      claims:
        policy:
          id_token: ['preferred_username']
    ```
    ```sh
    kubectl apply -f ./oidc_client.yaml
    ```

5. Modify Authelia Helm release's `values.yaml` to add the OIDC config:

   ```yaml
   pod:
      extraVolumes:
        - name: oidc
          secret:
            secretName: default-oidc
            items:
              - key: "authelia.oidc.yaml"
                path: "authelia.oidc.yaml"

      extraVolumeMounts:
        - mountPath: /oidc/authelia.oidc.yaml
          name: oidc
          readOnly: true
          subPath: authelia.oidc.yaml

   configMap:
      extraConfigs:
        - '/oidc/authelia.oidc.yaml'
   ```

### How it works
This project aims to follow the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/)
which provides a reconcile function responsible for synchronizing resources untile the desired state is reached on the cluster

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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
