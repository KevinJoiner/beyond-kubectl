package main

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

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

func Keys(rule *rbacv1.PolicyRule) ([]string, int) {
	groups := rule.APIGroups
	if len(groups) == 0 {
		groups = []string{"*"}
	}
	resources := rule.Resources
	if len(resources) == 0 {
		resources = []string{"*"}
	}
	resourceNames := rule.ResourceNames
	if len(resourceNames) == 0 {
		resourceNames = []string{"*"}
	}
	maxSize := 0
	keys := make([]string, 0, len(groups)*len(resources)*len(resourceNames))
	for _, group := range groups {
		for _, resource := range resources {
			for _, resourceName := range resourceNames {
				maxSize = max(maxSize, len(resourceName), len(resource), len(group))
				keys = append(keys, fmt.Sprintf("%s\t%s\t%s\t", resourceName, resource, group))
			}
		}
	}

	return keys, maxSize
}

func dedupRules(list map[string]map[string]struct{}, rules []rbacv1.PolicyRule) *tabwriter.Writer {
	maxSize := 0
	for i := range rules {
		keys, maxKey := Keys(&rules[i])
		maxSize = max(maxSize, maxKey)
		for _, key := range keys {
			verbs := list[key]
			if verbs == nil {
				verbs = make(map[string]struct{})
			}
			for _, verb := range rules[i].Verbs {
				verbs[verb] = struct{}{}
			}
			list[key] = verbs
		}
	}
	return tabwriter.NewWriter(os.Stdout, 0, maxSize, 1, ' ', 0)
}

func max(nums ...int) int {
	max := math.MinInt
	for num := range nums {
		if num > max {
			max = num
		}
	}
	return max
}

func printRules(rules []rbacv1.PolicyRule) {
	list := map[string]map[string]struct{}{}
	writer := dedupRules(list, rules)
	builder := strings.Builder{}
	keys := make([]string, len(list))
	i := 0
	for key := range list {
		keys[i] = key
		i++
	}
	sort.Strings(keys)

	for _, key := range keys {
		builder.Reset()
		builder.WriteString(key)
		verbMap := list[key]
		verbs := make([]string, len(verbMap))
		i := 0
		for verb := range verbMap {
			if verb == "*" {
				// only print * if present
				verbs = []string{"*"}
				break
			}
			verbs[i] = verb
			i++
		}
		sort.Strings(verbs)

		builder.WriteString(" [")
		for _, verb := range verbs {
			builder.WriteByte(' ')
			builder.WriteString(verb)
		}
		builder.WriteString(" ]\n")
		fmt.Fprint(writer, builder.String())
	}
	err := writer.Flush()
	if err != nil {
		fmt.Printf("Error: Failed to flush results to stdout: %s\n", err.Error())
	}
}
