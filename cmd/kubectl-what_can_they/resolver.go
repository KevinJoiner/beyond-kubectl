package main

import (
	"fmt"

	"github.com/rancher/lasso/pkg/controller"
	"github.com/rancher/wrangler/pkg/generic"
	"github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

type RBACRestGetter struct {
	Roles               generic.ClientInterface[*rbacv1.Role, *rbacv1.RoleList]
	RoleBindings        generic.ClientInterface[*rbacv1.RoleBinding, *rbacv1.RoleBindingList]
	ClusterRoles        generic.ClientInterface[*rbacv1.ClusterRole, *rbacv1.ClusterRoleList]
	ClusterRoleBindings generic.ClientInterface[*rbacv1.ClusterRoleBinding, *rbacv1.ClusterRoleBindingList]
}

// GetRole gets role within the given namespace that matches the provided name.
func (r RBACRestGetter) GetRole(namespace, name string) (*rbacv1.Role, error) {
	role, err := r.Roles.Get(namespace, name, v1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("failed to get role for '%s' in namespace '%s': %w", name, namespace, err)
		logrus.Debug(err)
	}
	return role, err
}

// ListRoleBindings list all roleBindings in the given namespace.
func (r RBACRestGetter) ListRoleBindings(namespace string) ([]*rbacv1.RoleBinding, error) {
	list, err := r.RoleBindings.List(namespace, v1.ListOptions{})
	ret := make([]*rbacv1.RoleBinding, len(list.Items))
	for i := range list.Items {
		ret[i] = &list.Items[i]
	}
	if err != nil {
		err = fmt.Errorf("failed to list roles in namespace '%s': %w", namespace, err)
		logrus.Debug(err)
	}
	return ret, err
}

// GetClusterRole gets the clusterRole with the given name.
func (r RBACRestGetter) GetClusterRole(name string) (*rbacv1.ClusterRole, error) {
	role, err := r.ClusterRoles.Get("", name, v1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("failed to get clusterRole '%s': %w", name, err)
		logrus.Debug(err)
	}
	return role, err
}

// ListClusterRoleBindings list all clusterRoleBindings.
func (r RBACRestGetter) ListClusterRoleBindings() ([]*rbacv1.ClusterRoleBinding, error) {
	list, err := r.ClusterRoleBindings.List("", v1.ListOptions{})
	ret := make([]*rbacv1.ClusterRoleBinding, len(list.Items))
	for i := range list.Items {
		ret[i] = &list.Items[i]
	}
	if err != nil {
		err = fmt.Errorf("failed to list clusterRoles: %w", err)
		logrus.Debug(err)
	}
	return ret, err
}

func DefaultResolver(ctrlFactory controller.SharedControllerFactory) validation.AuthorizationRuleResolver {
	rbacRestGetter := RBACRestGetter{
		Roles:               generic.NewController[*rbacv1.Role, *rbacv1.RoleList](rbacv1.SchemeGroupVersion.WithKind("Role"), "roles", true, ctrlFactory),
		RoleBindings:        generic.NewController[*rbacv1.RoleBinding, *rbacv1.RoleBindingList](rbacv1.SchemeGroupVersion.WithKind("RoleBinding"), "rolebindings", true, ctrlFactory),
		ClusterRoles:        generic.NewController[*rbacv1.ClusterRole, *rbacv1.ClusterRoleList](rbacv1.SchemeGroupVersion.WithKind("ClusterRole"), "clusterroles", false, ctrlFactory),
		ClusterRoleBindings: generic.NewController[*rbacv1.ClusterRoleBinding, *rbacv1.ClusterRoleBindingList](rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding"), "clusterrolebindings", false, ctrlFactory),
	}
	return validation.NewDefaultRuleResolver(rbacRestGetter, rbacRestGetter, rbacRestGetter, rbacRestGetter)
}
