/*
Copyright 2022 The Crossplane Authors.

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

package cluster

import (
	"context"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/crossplane/provider-rosa/apis/openshift/v1alpha1"
	apisv1alpha1 "github.com/crossplane/provider-rosa/apis/v1alpha1"
	"github.com/crossplane/provider-rosa/internal/controller/features"
	"github.com/crossplane/provider-rosa/util"
	"github.com/openshift/rosa/pkg/aws"
	"github.com/openshift/rosa/pkg/config"
	"github.com/openshift/rosa/pkg/ocm"
	"github.com/openshift/rosa/pkg/rosa"
)

const (
	errNotCluster   = "managed resource is not a Cluster custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"
	errNewClient    = "cannot create new Service"
)

// Setup adds a controller that reconciles Cluster managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.ClusterGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	rosaClient := rosa.NewRuntime()

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.ClusterGroupVersionKind),
		managed.WithExternalConnecter(&connector{
			kube:       mgr.GetClient(),
			usage:      resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			rosaClient: rosaClient}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...))

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		For(&v1alpha1.Cluster{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube       client.Client
	usage      resource.Tracker
	rosaClient *rosa.Runtime
}

// htpasswdIDP returns the htpasswd identity provider
type htpasswdIDP struct {
	htpasswdUser     string
	htpasswdPassword string
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Cluster)
	if !ok {
		return nil, errors.New(errNotCluster)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	cd := pc.Spec.Credentials
	openshiftToken, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	htpasswdUserSecretRef := pc.Spec.HTPasswdUser
	htpasswdUser, err := resource.CommonCredentialExtractor(ctx, htpasswdUserSecretRef.Source, c.kube, htpasswdUserSecretRef.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	htpasswdPasswordSecretRef := pc.Spec.HTPasswdPass
	htpasswdPassword, err := resource.CommonCredentialExtractor(ctx, htpasswdPasswordSecretRef.Source, c.kube, htpasswdPasswordSecretRef.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	htpasswdIDP := htpasswdIDP{
		htpasswdUser:     string(htpasswdUser),
		htpasswdPassword: string(htpasswdPassword),
	}

	cfg := new(config.Config)
	cfg.AccessToken = string(openshiftToken)
	c.rosaClient.OCMClient, err = ocm.NewClient().
		Config(cfg).
		Logger(c.rosaClient.Logger).
		Build()

	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}
	_, _, err = c.rosaClient.OCMClient.GetConnectionTokens()
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}
	rosaClient := c.rosaClient.WithOCM()
	awsClient := aws.GetAWSClientForUserRegion(rosaClient.Reporter, rosaClient.Logger)

	creator, err := awsClient.GetCreator()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get creator")
	}
	return &external{rosaClient: rosaClient, awsClient: &awsClient, creator: creator, htpasswdIDP: htpasswdIDP}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	rosaClient *rosa.Runtime
	awsClient  *aws.Client
	creator    *aws.Creator
	htpasswdIDP
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Cluster)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotCluster)
	}

	cluster, err := c.rosaClient.OCMClient.GetCluster(cr.Name, c.creator)
	if err != nil {
		if util.ErrNotFound(err) {
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil
		}
		return managed.ExternalObservation{ResourceExists: false}, err
	}
	var conn managed.ConnectionDetails
	status, _ := cluster.GetStatus()
	if status.State() == "ready" {
		cr.Status.AtProvider.ClusterID = cluster.ID()
		cr.Status.AtProvider.DNS = cluster.DNS().BaseDomain()
		cr.Status.AtProvider.DetailesPage = cluster.Console().URL()
		if !cr.Status.AtProvider.UserCreated {
			err := util.CreateAdminUser(c.htpasswdIDP.htpasswdUser, c.htpasswdIDP.htpasswdPassword, c.rosaClient, *c.awsClient, cluster)
			if err != nil {
				return managed.ExternalObservation{}, err
			}
			conn = managed.ConnectionDetails{
				xpv1.ResourceCredentialsSecretUserKey:     []byte(c.htpasswdIDP.htpasswdUser),
				xpv1.ResourceCredentialsSecretPasswordKey: []byte(c.htpasswdIDP.htpasswdPassword),
				xpv1.ResourceCredentialsSecretEndpointKey: []byte(cluster.API().URL()),
			}
			cr.Status.AtProvider.UserCreated = true
			cr.Status.SetConditions(xpv1.Available())
		}
	} else {
		cr.Status.SetConditions(xpv1.Unavailable())
	}
	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  true,
		ConnectionDetails: conn,
	}, nil
}

// Create attempts to create the external resource using the supplied managed
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Cluster)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotCluster)
	}

	credRequests, err := c.rosaClient.OCMClient.GetCredRequests(cr.Spec.ForProvider.Hypershift)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	cluster, err := c.rosaClient.OCMClient.CreateCluster(util.ClusterConfig(cr, credRequests))
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	err = util.CreateRoles(c.rosaClient, *c.awsClient, cr.Name, cluster, cr.Spec.ForProvider.Version, cr.Spec.ForProvider.AWSAccountID)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	err = util.CreateProvider(c.rosaClient, *c.awsClient, cluster)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	cr.Status.SetConditions(xpv1.Creating())
	return managed.ExternalCreation{}, nil
}

// Update attempts to update the external resource to match the managed resource.
func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Cluster)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotCluster)
	}
	credRequests, err := c.rosaClient.OCMClient.GetCredRequests(true)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	c.rosaClient.OCMClient.UpdateCluster(cr.Name, c.creator, util.ClusterConfig(cr, credRequests))
	return managed.ExternalUpdate{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// Delete attempts to delete the external resource.
func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Cluster)
	if !ok {
		return errors.New(errNotCluster)
	}
	cluster, err := c.rosaClient.OCMClient.GetCluster(cr.Name, c.creator)
	if err != nil {
		return err
	}
	cr.Status.SetConditions(xpv1.Deleting())
	c.rosaClient.OCMClient.DeleteCluster(cr.Name, c.creator)

	err = util.DeleteProvider(c.rosaClient, *c.awsClient, cluster)
	if err != nil {
		return err
	}

	err = util.DeleteRoles(c.rosaClient, *c.awsClient, cluster)
	if err != nil {
		return err
	}
	return nil
}
