package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/rancher/lasso/pkg/controller"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/generic"
	"github.com/rancher/wrangler/pkg/kubeconfig"
	"github.com/rancher/wrangler/pkg/schemes"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	userAttributePrincipalID = "principalid"
	userAttributeUserName    = "username"
)

type Namespaces []string

func (i *Namespaces) String() string {
	return "namespaces"
}

func (n *Namespaces) Set(value string) error {
	all := strings.Split(value, ",")
	*n = append(*n, all...)
	return nil
}

var myFlags Namespaces

func main() {
	var userName string
	var namespaces Namespaces
	var allNamespace bool
	flag.StringVar(&userName, "user", "", "user to resolve rules for")
	flag.Var(&namespaces, "namespace", "Namespace to use for listing rules")
	flag.BoolVar(&allNamespace, "A", false, "list rules for each namespace")
	flag.Parse()
	if userName == "" {
		log.Fatal("must specify a user")
	}
	if len(namespaces) == 0 {
		_ = namespaces.Set("")
	}
	kubeconfigPath := os.Getenv("KUBECONFIG")
	restCfg, err := kubeconfig.GetNonInteractiveClientConfig(kubeconfigPath).ClientConfig()
	if err != nil {
		log.Fatalf("Failed to create rest Config: %s", err.Error())
	}

	ctrlFactory, err := controller.NewSharedControllerFactoryFromConfig(restCfg, schemes.All)
	if err != nil {
		log.Fatalf("Failed to create client factory: %s", err.Error())
	}
	if allNamespace {
		nsClient, err := ctrlFactory.SharedCacheFactory().SharedClientFactory().ForKind(corev1.SchemeGroupVersion.WithKind("Namespace"))
		if err != nil {
			log.Fatalf("Failed to get create client for Namespaces: %s", err.Error())
		}
		nsList := &corev1.NamespaceList{}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
		err = nsClient.List(ctx, "", nsList, metav1.ListOptions{})
		if err != nil {
			log.Fatalf("Failed to list Namespaces: %s", err.Error())
		}
		cancel()
		namespaces = make([]string, len(nsList.Items))
		for i := range nsList.Items {
			namespaces[i] = nsList.Items[i].Name
		}
	}

	userCtrl := generic.NewController[*apisv3.User, *apisv3.UserList](apisv3.SchemeGroupVersion.WithKind("User"), apisv3.UserResourceName, false, ctrlFactory)
	userAttCtrl := generic.NewController[*apisv3.UserAttribute, *apisv3.UserAttributeList](apisv3.SchemeGroupVersion.WithKind("UserAttribute"), apisv3.UserAttributeResourceName, false, ctrlFactory)
	userv3, err := userCtrl.Get("", userName, metav1.GetOptions{})
	if err != nil {
		log.Fatalf("Failed to get user: %s", err.Error())
	}

	resolver := DefaultResolver(ctrlFactory)
	userInfo, err := getUserInfo(userv3, userAttCtrl)
	if err != nil {
		log.Fatalf("Failed to get userInfo: %s", err.Error())
	}
	for _, ns := range namespaces {
		rules, err := resolver.RulesFor(userInfo, ns)
		fmt.Printf("\nRules for Namespace: '%s'\n", ns)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Warning] Failed to resolve all rules: %s\n", err.Error())
		}
		printRules(rules)
	}
}
