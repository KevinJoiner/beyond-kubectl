package main

import (
	"strings"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/generic"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8suser "k8s.io/apiserver/pkg/authentication/user"
)

// getUserInfo gets a k8suser.Info (groups, username, uid, extras) for a given userID
// userID is the name of the v3.User object that we want to get info for
func getUserInfo(user *apisv3.User, attributeCache generic.ClientInterface[*apisv3.UserAttribute, *apisv3.UserAttributeList]) (k8suser.Info, error) {
	attribute, err := attributeCache.Get("", user.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// extras are created on first login. If the user hasn't logged in yet, do the best we can with only
			// the name in consideration.
			extras := make(map[string][]string)
			addExtrasFromUser(user, extras)
			return &k8suser.DefaultInfo{
				Name:   user.Name,
				UID:    user.Name,
				Groups: []string{k8suser.AllAuthenticated, "system:cattle:authenticated"},
				Extra:  extras,
			}, nil
		}
		return nil, err
	}
	var groups []string
	for _, group := range attribute.GroupPrincipals {
		for _, principal := range group.Items {
			name := strings.TrimPrefix(principal.Name, "local://")
			groups = append(groups, name)
		}
	}
	groups = append(groups, k8suser.AllAuthenticated, "system:cattle:authenticated")
	info := k8suser.DefaultInfo{
		Name:   user.Name,
		UID:    user.Name,
		Groups: groups,
		Extra:  getExtras(user, attribute),
	}
	return &info, nil
}

func getExtras(user *apisv3.User, attributes *apisv3.UserAttribute) map[string][]string {
	extras := make(map[string][]string)
	if attributes != nil && attributes.ExtraByProvider != nil && len(attributes.ExtraByProvider) != 0 {
		for _, extra := range attributes.ExtraByProvider {
			for key, value := range extra {
				extras[key] = append(extras[key], value...)
			}
		}
		return extras
	}
	addExtrasFromUser(user, extras)
	return extras
}

func addExtrasFromUser(user *apisv3.User, extras map[string][]string) {
	if len(extras[userAttributePrincipalID]) == 0 {
		extras[userAttributePrincipalID] = user.PrincipalIDs
	}
	if len(extras[userAttributeUserName]) == 0 {
		extras[userAttributeUserName] = []string{user.DisplayName}
	}
}
