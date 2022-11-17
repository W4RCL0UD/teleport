/*
Copyright 2022 Gravitational, Inc.

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

package kubernetestoken

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/gravitational/trace"
	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/strings/slices"
)

const (
	ServiceAccountGroup      = "system:serviceaccounts"
	ServiceAccountNamePrefix = "system:serviceaccount"
	ExtraDataPodNameField    = "authentication.kubernetes.io/pod-name"
)

type Validator struct {
	mu sync.Mutex
	// client is protected by mu and should only be accessed via the getProvider
	// method.
	client kubernetes.Interface
}

// getClient allows the lazy initialisation of the Kubernetes client
func (v *Validator) getClient() (kubernetes.Interface, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.client != nil {
		return v.client, nil
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, trace.WrapWithMessage(err, "failed to initialize in-cluster Kubernetes config")
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, trace.WrapWithMessage(err, "failed to initialize in-cluster Kubernetes client")
	}

	v.client = client
	return client, nil
}

// Validate uses the Kubernetes TokenReview API to validate a token and return its UserInfo
func (v *Validator) Validate(ctx context.Context, token string) (*v1.UserInfo, error) {
	client, err := v.getClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	review := &v1.TokenReview{
		Spec: v1.TokenReviewSpec{
			Token: token,
		},
	}
	options := metav1.CreateOptions{}

	reviewResult, err := client.AuthenticationV1().TokenReviews().Create(ctx, review, options)
	if err != nil {
		return nil, trace.WrapWithMessage(err, "error during the Kubernetes TokenReview")
	}

	if !reviewResult.Status.Authenticated {
		return nil, trace.AccessDenied("kubernetes failed to validate token: %s", reviewResult.Status.Error)
	}

	// Legacy tokens are long-lived and not bound to pods. We should not accept them if the cluster supports
	// bound tokens. Bound token support is GA since 1.20 and volume projection is beta since 1.21.
	// We can expect any 1.21+ cluster to use bound tokens.
	kubeVersion, err := client.Discovery().ServerVersion()
	if err != nil {
		return nil, trace.WrapWithMessage(err, "error during the kubernetes version check")
	}

	boundTokenSupport, err := kubernetesSupportsBoundTokens(kubeVersion)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Check the Username is a service account.
	// A user token would not match rules anyway, but we can produce a more relevant error message here.
	if !strings.HasPrefix(reviewResult.Status.User.Username, ServiceAccountNamePrefix) {
		return nil, trace.BadParameter("token user is not a service account: %s", reviewResult.Status.User.Username)
	}

	if !slices.Contains(reviewResult.Status.User.Groups, ServiceAccountGroup) {
		return nil, trace.BadParameter("token user '%s' does not belong to the '%s' group", reviewResult.Status.User.Username, ServiceAccountGroup)
	}

	// We know if the token is bound to a pod if its name is in the Extra userInfo.
	// If the token is not bound while Kubernetes supports bound tokens we abort.
	if _, ok := reviewResult.Status.User.Extra[ExtraDataPodNameField]; !ok && boundTokenSupport {
		return nil, trace.BadParameter(
			"legacy SA tokens are not accepted as kubernetes version %s supports bound tokens",
			kubeVersion.GitVersion,
		)
	}

	return &reviewResult.Status.User, nil
}

func kubernetesSupportsBoundTokens(info *version.Info) (bool, error) {
	major, err := strconv.Atoi(info.Major)
	if err != nil {
		return false, err
	}
	minor, err := strconv.Atoi(info.Minor)
	if err != nil {
		return false, err
	}

	if major > 1 {
		return true, nil
	}
	return minor > 20, nil
}
