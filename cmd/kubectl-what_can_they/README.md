# what-can-i
Prints a list of all rules held by a given user in a given namespace in Rancher for the local cluster.
Output has the following format:
`ResourceName` `Resource` `Group` [ `Verbs` ]
``` bash
kubectl what-can-they --user="u-6tkvj" --namespace="c-k4mkf"

Rules for Namespace: 'c-k4mkf'
*            *                                          *                             [ get ]
*            *                                          rke-machine-config.cattle.io  [ create get watch ]
*            *                                          rke-machine.cattle.io         [ get watch ]
*            apiservices                                apiregistration.k8s.io        [ get list watch ]
*            catalogs                                   management.cattle.io          [ get list watch ]
*            catalogtemplates                           management.cattle.io          [ get list watch ]
*            catalogtemplateversions                    management.cattle.io          [ get list watch ]
*            cisbenchmarkversions                       management.cattle.io          [ get list watch ]
*            cisconfigs                                 management.cattle.io          [ get list watch ]
*            clusteralertgroups                         management.cattle.io          [ get list watch ]
*            clusteralertrules                          management.cattle.io          [ get list watch ]
*            clustercatalogs                            management.cattle.io          [ get list watch ]
*            clusterevents                              management.cattle.io          [ get list watch ]
*            clusterloggings                            management.cattle.io          [ get list watch ]
*            clustermonitorgraphs                       management.cattle.io          [ get list watch ]
*            clusterrepos                               catalog.cattle.io             [ get list watch ]
*            clusterroletemplatebindings                management.cattle.io          [ get list watch ]
*            clusters                                   management.cattle.io          [ create ]
*            clusters                                   provisioning.cattle.io        [ create get watch ]
*            clustertemplaterevisions                   management.cattle.io          [ create ]
*            features                                   management.cattle.io          [ get list watch ]
*            fleetworkspaces                            management.cattle.io          [ create ]
*            globaldnses                                management.cattle.io          [ create ]
*            globaldnsproviders                         management.cattle.io          [ create ]
*            kontainerdrivers                           management.cattle.io          [ get list watch ]
*            machinedeployments                         cluster.x-k8s.io              [ get watch ]
*            machines                                   cluster.x-k8s.io              [ get watch ]
*            multiclusterapps                           management.cattle.io          [ create ]
*            navlinks                                   ui.cattle.io                  [ get list watch ]
*            nodedrivers                                management.cattle.io          [ get list watch ]
*            nodemetrics                                metrics.k8s.io                [ get list watch ]
*            nodepools                                  management.cattle.io          [ get list watch ]
*            nodes                                                                    [ get list watch ]
*            nodes                                      management.cattle.io          [ get list watch ]
*            nodes                                      metrics.k8s.io                [ get list watch ]
*            nodetemplates                              management.cattle.io          [ create ]
*            notifiers                                  management.cattle.io          [ get list watch ]
*            persistentvolumes                                                        [ get list watch ]
*            podsecurityadmissionconfigurationtemplates management.cattle.io          [ get list watch ]
*            podsecuritypolicytemplates                 management.cattle.io          [ get list watch ]
*            preferences                                management.cattle.io          [ * ]
*            principals                                 management.cattle.io          [ get list watch ]
*            projects                                   management.cattle.io          [ create ]
*            rancherusernotifications                   management.cattle.io          [ get list watch ]
*            rkeaddons                                  management.cattle.io          [ get list watch ]
*            rkek8sserviceoptions                       management.cattle.io          [ get list watch ]
*            rkek8ssystemimages                         management.cattle.io          [ get list watch ]
*            roletemplates                              management.cattle.io          [ get list watch ]
*            secrets                                                                  [ create ]
*            selfsubjectaccessreviews                   authorization.k8s.io          [ create ]
*            selfsubjectrulesreviews                    authorization.k8s.io          [ create ]
*            settings                                   management.cattle.io          [ get list watch ]
*            sourcecodecredentials                      project.cattle.io             [ * ]
*            sourcecoderepositories                     project.cattle.io             [ * ]
*            storageclasses                             storage.k8s.io                [ get list watch ]
*            templates                                  management.cattle.io          [ get list watch ]
*            templateversions                           management.cattle.io          [ get list watch ]
c-k4mkf      clusters                                   management.cattle.io          [ get ]
c-m-q2vvvnjn clusters                                   management.cattle.io          [ * ]
local        clusters                                   management.cattle.io          [ get ]
u-6tkvj      users                                      management.cattle.io          [ get ]
```