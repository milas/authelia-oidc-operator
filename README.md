# authelia-oidc-operator
Manage [OIDC]() clients for [Authelia](https://www.authelia.com/) SSO using Kubernetes CRDs.

## Status
⚠ **ALPHA** - APIs may change and test coverage is limited!

- [x] `OIDCProvider` CRD
- [x] `OIDCClient` CRD
- [ ] Helm chart
- [ ] Status updates on CRDs

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
      cors:
        allowed_origins:
          - https://example.com
    ```
    ```sh
    kubectl apply -f ./oidc_provider.yaml
    ```
4. Create an `OIDCClient`:

    **`oidc_client.yaml`**
    ```yaml
    apiVersion: authelia.milas.dev/v1alpha1
    kind: OIDCClient
    metadata:
      name: my-client
      namespace: my-app
      annotations:
        authelia.milas.dev/oidc-provider: authelia/default
    spec:
      id: myapp
      description: My Application
      secret_ref:
        key: 'OIDC_CLIENT_SECRET'
        name: 'my-app'
      public: false
      authorization_policy: two_factor
      redirect_uris:
        - https://oidc.example.com:8080/oauth2/callback
    ```
    ```sh
    kubectl apply -f ./oidc_client.yaml
    ```

5. Modify Authelia Deployment to find OIDC config
    > COMING SOON!

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
