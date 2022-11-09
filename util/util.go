package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/crossplane/provider-rosa/apis/openshift/v1alpha1"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/rosa/cmd/create/idp"
	"github.com/openshift/rosa/pkg/aws"
	"github.com/openshift/rosa/pkg/aws/tags"
	"github.com/openshift/rosa/pkg/ocm"
	"github.com/openshift/rosa/pkg/rosa"
)

// ErrNotFound is returned when a resource is not found
func ErrNotFound(err error) bool {
	return strings.Contains(err.Error(), "There is no cluster with identifier or name")
}

// ErrUserAlreadyExists is returned when a user already exists
func ErrUserAlreadyExists(err error) bool {
	return strings.Contains(err.Error(), "already exists on group")
}

// getRoleNameAndARN returns the role name and ARN for the given operator
func getOperatorRoleArn(prefix string, operator *cmv1.STSOperator, awsAccountID string) string {
	role := fmt.Sprintf("%s-%s-%s", prefix, operator.Namespace(), operator.Name())
	if len(role) > 64 {
		role = role[0:64]
	}
	str := fmt.Sprintf("arn:aws:iam::%s:role", awsAccountID)
	return fmt.Sprintf("%s/%s", str, role)
}

// operatorIAMRole returns the operator IAM role for the given cluster
func operatorIAMRole(cr *v1alpha1.Cluster, credRequests map[string]*cmv1.STSOperator) []ocm.OperatorIAMRole {
	operatorIAMRoleList := []ocm.OperatorIAMRole{}
	for _, operator := range credRequests {
		operatorIAMRoleList = append(operatorIAMRoleList, ocm.OperatorIAMRole{
			Name:      operator.Name(),
			Namespace: operator.Namespace(),
			RoleARN:   getOperatorRoleArn(cr.Name, operator, cr.Spec.ForProvider.AWSAccountID),
		})
	}
	return operatorIAMRoleList
}

// ClusterConfig contains the configuration for a cluster
func ClusterConfig(cr *v1alpha1.Cluster, credRequests map[string]*cmv1.STSOperator) ocm.Spec {
	return ocm.Spec{
		Name:                          cr.Name,
		Region:                        cr.Spec.ForProvider.Region,
		MultiAZ:                       cr.Spec.ForProvider.MultiAZ,
		Version:                       "openshift-v" + cr.Spec.ForProvider.Version,
		ChannelGroup:                  cr.Spec.ForProvider.ChannelGroup,
		Expiration:                    cr.Spec.ForProvider.Expiration.Time,
		Flavour:                       cr.Spec.ForProvider.Flavour,
		DisableWorkloadMonitoring:     cr.Spec.ForProvider.DisableWorkloadMonitoring,
		FIPS:                          cr.Spec.ForProvider.FIPS,
		EtcdEncryption:                cr.Spec.ForProvider.EtcdEncryption,
		KMSKeyArn:                     cr.Spec.ForProvider.KMSKeyArn,
		ComputeMachineType:            cr.Spec.ForProvider.ComputeMachineType,
		ComputeNodes:                  cr.Spec.ForProvider.ComputeNodes,
		Autoscaling:                   cr.Spec.ForProvider.Autoscaling,
		MinReplicas:                   cr.Spec.ForProvider.MinReplicas,
		MaxReplicas:                   cr.Spec.ForProvider.MaxReplicas,
		SubnetIds:                     cr.Spec.ForProvider.SubnetIds,
		AvailabilityZones:             cr.Spec.ForProvider.AvailabilityZones,
		NetworkType:                   cr.Spec.ForProvider.NetworkType,
		MachineCIDR:                   net.IPNet{IP: net.IP(cr.Spec.ForProvider.MachineCIDR.IP), Mask: net.IPMask(cr.Spec.ForProvider.MachineCIDR.Mask)},
		ServiceCIDR:                   net.IPNet{IP: net.IP(cr.Spec.ForProvider.ServiceCIDR.IP), Mask: net.IPMask(cr.Spec.ForProvider.ServiceCIDR.Mask)},
		PodCIDR:                       net.IPNet{IP: net.IP(cr.Spec.ForProvider.PodCIDR.IP), Mask: net.IPMask(cr.Spec.ForProvider.PodCIDR.Mask)},
		HostPrefix:                    cr.Spec.ForProvider.HostPrefix,
		Private:                       cr.Spec.ForProvider.Private,
		PrivateLink:                   cr.Spec.ForProvider.PrivateLink,
		CustomProperties:              cr.Spec.ForProvider.CustomProperties,
		Tags:                          cr.Spec.ForProvider.Tags,
		DryRun:                        cr.Spec.ForProvider.DryRun,
		DisableSCPChecks:              cr.Spec.ForProvider.DisableSCPChecks,
		IsSTS:                         cr.Spec.ForProvider.IsSTS,
		RoleARN:                       cr.Spec.ForProvider.RoleARN,
		ExternalID:                    cr.Spec.ForProvider.ExternalID,
		SupportRoleARN:                cr.Spec.ForProvider.SupportRoleARN,
		OperatorIAMRoles:              operatorIAMRole(cr, credRequests),
		ControlPlaneRoleARN:           cr.Spec.ForProvider.ControlPlaneRoleARN,
		WorkerRoleARN:                 cr.Spec.ForProvider.WorkerRoleARN,
		Mode:                          cr.Spec.ForProvider.Mode,
		NodeDrainGracePeriodInMinutes: float64(cr.Spec.ForProvider.NodeDrainGracePeriodInMinutes),
		EnableProxy:                   cr.Spec.ForProvider.EnableProxy,
		HTTPProxy:                     cr.Spec.ForProvider.HTTPProxy,
		HTTPSProxy:                    cr.Spec.ForProvider.HTTPSProxy,
		NoProxy:                       cr.Spec.ForProvider.NoProxy,
		AdditionalTrustBundleFile:     cr.Spec.ForProvider.AdditionalTrustBundleFile,
		AdditionalTrustBundle:         cr.Spec.ForProvider.AdditionalTrustBundle,
		Hypershift: ocm.Hypershift{
			Enabled: cr.Spec.ForProvider.Hypershift,
		},
	}
}

// CreateRoles creates the roles required for the cluster
func CreateRoles(r *rosa.Runtime, awsClient aws.Client, prefix string, cluster *cmv1.Cluster, accountRoleVersion, accountID string) error {
	defaultPolicyVersion, err := r.OCMClient.GetDefaultVersion()
	if err != nil {
		return err
	}
	policies, err := r.OCMClient.GetPolicies("OperatorRole")
	if err != nil {
		return err
	}
	credRequests, err := r.OCMClient.GetCredRequests(cluster.Hypershift().Enabled())
	if err != nil {
		return err
	}
	for credrequest, operator := range credRequests {
		roleName := getRoleNameAndARN(cluster, operator)
		if roleName == "" {
			return fmt.Errorf("failed to find operator IAM role")
		}
		path, err := getPathFromInstallerRole(cluster)
		if err != nil {
			return err
		}
		policyARN := aws.GetOperatorPolicyARN(accountID, prefix, operator.Namespace(),
			operator.Name(), path)
		filename := fmt.Sprintf("openshift_%s_policy", credrequest)
		policyDetails := policies[filename]

		policyARN, err = awsClient.EnsurePolicy(policyARN, policyDetails,
			defaultPolicyVersion, map[string]string{
				tags.OpenShiftVersion: accountRoleVersion,
				tags.RolePrefix:       prefix,
				tags.RedHatManaged:    "true",
				"operator_namespace":  operator.Namespace(),
				"operator_name":       operator.Name(),
			}, path)
		if err != nil {
			return err
		}
		policyDetails = policies["operator_iam_role_policy"]
		policy, err := aws.GenerateOperatorRolePolicyDoc(cluster, accountID, operator, policyDetails)
		if err != nil {
			return err
		}
		_, err = awsClient.EnsureRole(roleName, policy, "", accountRoleVersion,
			map[string]string{
				tags.ClusterID:       cluster.ID(),
				"operator_namespace": operator.Namespace(),
				"operator_name":      operator.Name(),
				tags.RedHatManaged:   "true",
			}, path)
		if err != nil {
			return err
		}
		err = awsClient.AttachRolePolicy(roleName, policyARN)
		if err != nil {
			return err
		}
	}
	return nil
}

// getRoleNameAndARN returns the role name and ARN for the given operator
func getRoleNameAndARN(cluster *cmv1.Cluster, operator *cmv1.STSOperator) string {
	for _, role := range cluster.AWS().STS().OperatorIAMRoles() {
		if role.Namespace() == operator.Namespace() && role.Name() == operator.Name() {
			name, _ := aws.GetResourceIdFromARN(role.RoleARN())
			return name
		}
	}
	return ""
}

// getPathFromInstallerRole returns the path of the installer role
func getPathFromInstallerRole(cluster *cmv1.Cluster) (string, error) {
	return aws.GetPathFromARN(cluster.AWS().STS().RoleARN())
}

// createProvider creates the oidc provider for the cluster
func CreateProvider(r *rosa.Runtime, awsClient aws.Client, cluster *cmv1.Cluster) error {
	oidcEndpointURL := cluster.AWS().STS().OIDCEndpointURL()

	thumbprint, err := getThumbprint(oidcEndpointURL)
	if err != nil {
		return err
	}
	r.Reporter.Debugf("Using thumbprint '%s'", thumbprint)

	_, err = awsClient.CreateOpenIDConnectProvider(oidcEndpointURL, thumbprint[:40], cluster.ID())
	if err != nil {
		return err
	}
	return nil
}

// getThumbprint returns the thumbprint of the given URL
func getThumbprint(oidcEndpointURL string) (string, error) {
	connect, err := url.ParseRequestURI(oidcEndpointURL)
	if err != nil {
		return "", err
	}

	response, err := http.Get(fmt.Sprintf("https://%s:443", connect.Host))
	if err != nil {
		return "", err
	}

	certChain := response.TLS.PeerCertificates

	// Grab the CA in the chain
	for _, cert := range certChain {
		if cert.IsCA {
			if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
				return sha256Hash(cert.Raw), nil
			}
		}
	}

	// Fall back to using the last certficiate in the chain
	cert := certChain[len(certChain)-1]
	return sha256Hash(cert.Raw), nil
}

// sha1Hash computes the SHA1 of the byte array and returns the hex encoding as a string.
func sha256Hash(data []byte) string {
	// nolint:gosec
	hasher := sha256.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)
	return hex.EncodeToString(hashed)
}

// delteProvider deletes the oidc provider for the cluster
func DeleteProvider(r *rosa.Runtime, awsClient aws.Client, cluster *cmv1.Cluster) error {
	providerARN, err := awsClient.GetOpenIDConnectProvider(cluster.ID())
	if err != nil {
		return err
	}
	if providerARN != "" {
		err = awsClient.DeleteOpenIDConnectProvider(providerARN)
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteRoles deletes the operator roles for the cluster
func DeleteRoles(r *rosa.Runtime, awsClient aws.Client, cluster *cmv1.Cluster) error {
	credRequests, err := r.OCMClient.GetCredRequests(cluster.Hypershift().Enabled())
	if err != nil {
		return err
	}
	for _, operator := range credRequests {
		roleName := getRoleNameAndARN(cluster, operator)
		if roleName == "" {
			return fmt.Errorf("failed to find operator IAM role")
		}
		err = awsClient.DeleteOperatorRole(roleName)
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateAdminUser creates the admin user for the cluster
func CreateAdminUser(username, password string, r *rosa.Runtime, awsClient aws.Client, cluster *cmv1.Cluster) error {
	_, existingUserList := idp.FindExistingHTPasswdIDP(cluster, r)
	hasAdmin := false
	existingUserList.Each(func(user *cmv1.HTPasswdUser) bool {
		if user.Username() == username {
			hasAdmin = true
		}
		return true
	})

	if !hasAdmin {
		htpasswdIDP := cmv1.NewHTPasswdIdentityProvider().Users(cmv1.NewHTPasswdUserList().Items(
			idp.CreateHTPasswdUser(username, password),
		))

		newIDP, err := cmv1.NewIdentityProvider().
			Type("HTPasswdIdentityProvider").
			Name(idp.HTPasswdIDPName).
			Htpasswd(htpasswdIDP).
			Build()
		if err != nil {
			return err
		}

		_, err = r.OCMClient.CreateIdentityProvider(cluster.ID(), newIDP)
		if err != nil {
			return err
		}
	}
	return nil
}
