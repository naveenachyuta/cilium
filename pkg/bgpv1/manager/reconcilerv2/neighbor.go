// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
)

// NeighborReconciler is a ConfigReconciler which reconciles the peers of the
// provided BGP server with the provided CiliumBGPVirtualRouter.
type NeighborReconciler struct {
	DB           *statedb.DB
	logger       *slog.Logger
	SecretStore  store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig   store.BGPCPResourceStore[*v2.CiliumBGPPeerConfig]
	DaemonConfig *option.DaemonConfig
	metadata     map[string]NeighborReconcilerMetadata
}

type NeighborReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type NeighborReconcilerIn struct {
	cell.In

	Logger       *slog.Logger
	SecretStore  store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig   store.BGPCPResourceStore[*v2.CiliumBGPPeerConfig]
	DaemonConfig *option.DaemonConfig

	DB         *statedb.DB
	JobGroup   job.Group
	Signaler   *signaler.BGPCPSignaler
	RouteTable statedb.Table[*tables.Device]
}

func NewNeighborReconciler(params NeighborReconcilerIn) NeighborReconcilerOut {
	logger := params.Logger.With(types.ReconcilerLogField, "Neighbor")

	// Add observer for default gateway changes
	params.JobGroup.Add(
		job.Observer("default-gateway-tracker", func(ctx context.Context, event statedb.Change[*tables.Device]) error {
			device := event.Object
			fmt.Println("asdfdfdd", device.Name, device.Addrs, device.Index, device.OperStatus, device.RawFlags, device.Type, device)

			// columns := []string{"Destination", "Source", "Gateway", "LinkIndex", "Priority"}
			// idxs, err := getColumnIndexes(columns, header)
			// if err != nil {
			// 	return "", err
			// }
			// route := event.Object
			// a := event.Deleted
			// fmt.Println(route.Dst.String(), route.Priority, "llllllll")
			// fmt.Println("route", route, "assssssssffsdsdss", a)
			// b := event.Revision
			// fmt.Println("route", route, "assssssssffasfdsssdsdss", b)
			// // Check if this is a default route change
			// if route.Dst.String() == "0.0.0.0/0" || route.Dst.String() == "::/0" {
			// 	// Trigger reconciliation when there's a change in default routes
			// 	fmt.Println("signal triggereddd")
			// 	params.Signaler.Event(struct{}{})
			// 	params.Logger.Debug("Default gateway change detected, triggering BGP reconciliation")
			// }
			params.Signaler.Event(struct{}{})
			params.Logger.Debug("Default gateway change detected, triggering BGP reconciliation")
			return nil
		}, statedb.Observable(params.DB, params.RouteTable)),
	)

	return NeighborReconcilerOut{
		Reconciler: &NeighborReconciler{
			logger:       logger,
			DB:           params.DB,
			SecretStore:  params.SecretStore,
			PeerConfig:   params.PeerConfig,
			DaemonConfig: params.DaemonConfig,
			metadata:     make(map[string]NeighborReconcilerMetadata),
		},
	}
}

// PeerData keeps a peer and its configuration. It also keeps the TCP password from secret store.
// +deepequal-gen=true
// Note:  If you change PeerDate, do not forget to 'make generate-k8s-api', which will update DeepEqual method.
type PeerData struct {
	Peer     *v2.CiliumBGPNodePeer
	Config   *v2.CiliumBGPPeerConfigSpec
	Password string
}

// NeighborReconcilerMetadata keeps a map of running peers to peer configuration.
// Key is the peer name.
type NeighborReconcilerMetadata map[string]*PeerData

func (r *NeighborReconciler) getMetadata(i *instance.BGPInstance) NeighborReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *NeighborReconciler) upsertMetadata(i *instance.BGPInstance, d *PeerData) {
	if i == nil || d == nil {
		return
	}
	r.metadata[i.Name][d.Peer.Name] = d
}

func (r *NeighborReconciler) deleteMetadata(i *instance.BGPInstance, d *PeerData) {
	if i == nil || d == nil {
		return
	}
	delete(r.metadata[i.Name], d.Peer.Name)
}

func (r *NeighborReconciler) Name() string {
	return NeighborReconcilerName
}

// Priority of neighbor reconciler is higher than pod/service announcements.
// This is important for graceful restart case, where all expected routes are pushed
// into gobgp RIB before neighbors are added. So, gobgp can send out all prefixes
// within initial update message exchange with neighbors before sending EOR marker.
func (r *NeighborReconciler) Priority() int {
	return NeighborReconcilerPriority
}

func (r *NeighborReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = make(NeighborReconcilerMetadata)
	return nil
}

func (r *NeighborReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func getColumnIndexes(names []string, header []string) (map[string]int, error) {
	columnIndexes := make(map[string]int)
loop:
	for _, name := range names {
		for i, name2 := range header {
			if strings.EqualFold(name, name2) {
				columnIndexes[name] = i
				continue loop
			}
		}
		return nil, fmt.Errorf("column %q not part of %v", name, header)
	}
	return columnIndexes, nil
}

func (r *NeighborReconciler) getDefaultGateway(addressFamily string) (string, error) {
	// addressFamily = netlink.FAMILY_V4
	fmt.Println(addressFamily)
	txn := r.DB.ReadTxn()
	meta := r.DB.GetTable(txn, "routes")
	tbl := statedb.AnyTable{Meta: meta}
	objs := tbl.All(txn)

	deviceMeta := r.DB.GetTable(txn, "devices")
	deviceTbl := statedb.AnyTable{Meta: deviceMeta}
	deviceObjs := deviceTbl.All(txn)
	deviceHeader := deviceTbl.TableHeader()
	for _, head := range deviceHeader {
		fmt.Println("header123", head)
	}
	deviceColumns := []string{"Index", "OperStatus"}
	deviceIdxs, err := getColumnIndexes(deviceColumns, deviceHeader)
	if err != nil {
		return "", fmt.Errorf("failed to get column indexes for device table: %w", err)
	}
	for deviceObj := range deviceObjs {
		row := deviceObj.(statedb.TableWritable).TableRow()
		fmt.Println("devicessss", row)
	}
	// for obj := range objs {
	// 	fmt.Println("object", obj)
	// 	header := tbl.TableHeader()

	// 	var idxs []int
	// 	var err error

	// idxs, err = getColumnIndexes(header, header)

	// fmt.Println("idxsss", idxs, err)

	// fmt.Println("header123", header)
	// }

	// allTbls := r.DB.GetTables(txn)
	// fmt.Println(allTbls, "llsdlfldsflsd")
	// for _, tbls := range allTbls {
	// 	fmt.Println("llklklklklklkkl")
	// 	fmt.Println(tbls.Name())
	// 	fmt.Println(tbls.Indexes())
	// }
	header := tbl.TableHeader()
	defaultRoutes := [][]string{}
	columns := []string{"Destination", "Source", "Gateway", "LinkIndex", "Priority"}
	idxs, err := getColumnIndexes(columns, header)
	if err != nil {
		return "", err
	}
	//if rt.Flags&unix.RTNH_F_LINKDOWN != 0 || rt.Flags&unix.RTNH_F_DEAD != 0 {
	// continue
	// }
	for _, h1 := range header {
		fmt.Println(h1, "route header")
	}
	for obj := range objs {
		// row := takeColumns(obj.(statedb.TableWritable).TableRow(), idxs)
		row := obj.(statedb.TableWritable).TableRow()
		fmt.Println("rorrrwwwwww", row)
		if row[idxs["Gateway"]] != "" && row[idxs["Destination"]] != "" {
			if row[idxs["Destination"]] == "0.0.0.0/0" && addressFamily == "ipv4" {
				for deviceObj := range deviceObjs {
					row2 := deviceObj.(statedb.TableWritable).TableRow()
					fmt.Println("row22222", row2, deviceIdxs["OperStatus"], row2[deviceIdxs["Index"]], row[idxs["LinkIndex"]])
					if row2[deviceIdxs["Index"]] == row[idxs["LinkIndex"]] {
						fmt.Println("yesssfffaaaaaa")
						if row2[deviceIdxs["OperStatus"]] == "up" {
							fmt.Println("yesssfbbbbbbbbbbbbfadfgdfgmfdnldfnf")
							r.logger.Debug("Default gateway found1111", "gateway", row[idxs["Gateway"]])
							defaultRoutes = append(defaultRoutes, row)
							break
						}
					}
				}
			} else if row[idxs["Destination"]] == "::/0" && addressFamily == "ipv6" {
				for deviceObj := range deviceObjs {
					row2 := deviceObj.(statedb.TableWritable).TableRow()
					fmt.Println("row233333", row2, deviceIdxs["OperStatus"], row2[deviceIdxs["Index"]], row[idxs["LinkIndex"]])
					if row2[deviceIdxs["Index"]] == row[idxs["LinkIndex"]] {
						fmt.Println("yesssfff")
						if row2[deviceIdxs["OperStatus"]] == "up" {
							fmt.Println("yesssfbbbbbbbbbbbbff")
							r.logger.Debug("Default gateway found2222", "gateway", row[idxs["Gateway"]])
							defaultRoutes = append(defaultRoutes, row)
							break
						}
					}
				}
			}
		}
	}
	// netip.PrefixFrom(netip.IPv4Unspecified(), 0)

	fmt.Println(defaultRoutes, ";;;;;")
	if len(defaultRoutes) == 0 {
		return "", fmt.Errorf("failed to get default gateways from route table")
	}
	// sort the default routes by priority
	sort.Slice(defaultRoutes, func(i, j int) bool {
		return defaultRoutes[i][idxs["Priority"]] < defaultRoutes[j][idxs["Priority"]]
	})
	fmt.Println(defaultRoutes, ";;;;;ssssssss")
	fmt.Println(defaultRoutes[0])
	fmt.Println(defaultRoutes[0][idxs["Gateway"]])
	// return the gateway address with lowest priority
	return defaultRoutes[0][idxs["Gateway"]], nil
}

func (r *NeighborReconciler) configureDefaultGateway(defaultGateway *v2.DefaultGateway) (string, error) {
	peerAddress, err := r.getDefaultGateway(defaultGateway.AddressFamily)
	if err != nil {
		return "", fmt.Errorf("failed to get default gateway %w", err)
	}
	if peerAddress == "" {
		return peerAddress, fmt.Errorf("failed get default gateway. empty address")
	}

	return peerAddress, nil
}

func (r *NeighborReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	var (
		l = r.logger.With(types.InstanceLogField, p.DesiredConfig.Name)

		toCreate []*PeerData
		toRemove []*PeerData
		toUpdate []*PeerData
	)
	curNeigh := r.getMetadata(p.BGPInstance)
	newNeigh := p.DesiredConfig.Peers

	l.Debug("Begin reconciling peers")

	type member struct {
		new *PeerData
		cur *PeerData
	}

	nset := map[string]*member{}

	for i, n := range newNeigh {
		// validate that peer has ASN and address. In current implementation these fields are
		// mandatory for a peer. Eventually we will relax this restriction with implementation
		// of BGP unnumbered.
		if n.PeerASN == nil {
			return fmt.Errorf("peer %s does not have a PeerASN", n.Name)
		}

		if n.PeerAddress == nil {
			switch n.AutoDiscovery.Mode {
			case "default-gateway":
				defaultGateway, err := r.configureDefaultGateway(n.AutoDiscovery.DefaultGateway)
				if err != nil {
					r.logger.Error("failed to get default gateway", "error", err)
				}
				fmt.Println("fsdsds", defaultGateway, "lllll")
				newNeigh[i].PeerAddress = &defaultGateway
			default:
				r.logger.Debug("Peer does not have PeerAddress configured, skipping", types.PeerLogField, n.Name)
				continue
			}
		}
		fmt.Println(newNeigh[i], "lklskdls")
		var (
			key = r.neighborID(&newNeigh[i])
			h   *member
			ok  bool
		)

		config, exists, err := r.getPeerConfig(n.PeerConfigRef)
		if err != nil {
			return err
		}
		if !exists {
			continue // configured peer config does not exist, skip
		}

		passwd, err := r.getPeerPassword(p.DesiredConfig.Name, n.Name, config)
		if err != nil {
			return err
		}

		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				new: &PeerData{
					Peer:     &newNeigh[i],
					Config:   config,
					Password: passwd,
				},
			}
			continue
		}
		h.new = &PeerData{
			Peer:     &newNeigh[i],
			Config:   config,
			Password: passwd,
		}
	}

	for i, n := range curNeigh {
		var (
			key = r.neighborID(n.Peer)
			h   *member
			ok  bool
		)

		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				cur: curNeigh[i],
			}
			continue
		}
		h.cur = curNeigh[i]
	}

	for _, m := range nset {
		if m.new != nil {
			fmt.Println(*m.new.Peer.PeerAddress, "new")
		}
		if m.cur != nil {
			fmt.Println(*m.cur.Peer.PeerAddress, "current")
		}
		fmt.Printf("%v whattt", m)
		// present in new neighbors (set new) but not in current neighbors (set cur)
		if m.new != nil && m.cur == nil {
			toCreate = append(toCreate, m.new)
		}
		// present in current neighbors (set cur) but not in new neighbors (set new)
		if m.cur != nil && m.new == nil {
			toRemove = append(toRemove, m.cur)
		}
		// present in both new neighbors (set new) and current neighbors (set cur), update if they are not equal
		if m.cur != nil && m.new != nil {
			if !m.cur.DeepEqual(m.new) {
				toUpdate = append(toUpdate, m.new)
			}
		}
	}

	if len(toCreate) > 0 || len(toRemove) > 0 || len(toUpdate) > 0 {
		l.Info("Reconciling peers for instance")
	} else {
		l.Debug("No peer changes necessary")
	}

	// remove neighbors
	for _, n := range toRemove {
		l.Info("Removing peer", types.PeerLogField, n.Peer.Name, *n.Peer.PeerAddress, *n.Peer.PeerASN)

		if err := p.BGPInstance.Router.RemoveNeighbor(ctx, types.ToNeighborV2(n.Peer, n.Config, "")); err != nil {
			return fmt.Errorf("failed to remove neigbhor %s from instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.deleteMetadata(p.BGPInstance, n)
	}

	// update neighbors
	for _, n := range toUpdate {
		l.Info("Updating peer", types.PeerLogField, n.Peer.Name, *n.Peer.PeerAddress, *n.Peer.PeerASN)

		if err := p.BGPInstance.Router.UpdateNeighbor(ctx, types.ToNeighborV2(n.Peer, n.Config, n.Password)); err != nil {
			return fmt.Errorf("failed to update neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadata(p.BGPInstance, n)
	}

	// create new neighbors
	for _, n := range toCreate {
		l.Info("Adding peer", types.PeerLogField, n.Peer.Name, *n.Peer.PeerAddress, *n.Peer.PeerASN)

		if err := p.BGPInstance.Router.AddNeighbor(ctx, types.ToNeighborV2(n.Peer, n.Config, n.Password)); err != nil {
			return fmt.Errorf("failed to add neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadata(p.BGPInstance, n)
	}

	l.Debug("Done reconciling peers")
	return nil
}

// getPeerConfig returns the CiliumBGPPeerConfigSpec for the given peerConfig.
// If peerConfig is not specified, returns the default config.
// If the referenced peerConfig does not exist, exists returns false.
func (r *NeighborReconciler) getPeerConfig(peerConfig *v2.PeerConfigReference) (conf *v2.CiliumBGPPeerConfigSpec, exists bool, err error) {
	if peerConfig == nil || peerConfig.Name == "" {
		// if peer config is not specified, return default config
		conf = &v2.CiliumBGPPeerConfigSpec{}
		conf.SetDefaults()
		return conf, true, nil
	}

	config, exists, err := r.PeerConfig.GetByKey(resource.Key{Name: peerConfig.Name})
	if err != nil || !exists {
		if errors.Is(err, store.ErrStoreUninitialized) {
			err = errors.Join(err, ErrAbortReconcile)
		}
		return nil, exists, err
	}

	conf = &config.Spec
	conf.SetDefaults()
	return conf, true, nil
}

func (r *NeighborReconciler) getPeerPassword(instanceName, peerName string, config *v2.CiliumBGPPeerConfigSpec) (string, error) {
	if config == nil {
		return "", nil
	}

	if config.AuthSecretRef != nil {
		secretRef := *config.AuthSecretRef

		secret, ok, err := r.fetchSecret(secretRef)
		if err != nil {
			return "", fmt.Errorf("failed to fetch secret %q: %w", secretRef, err)
		}
		if !ok {
			return "", nil
		}
		tcpPassword := string(secret["password"])
		if tcpPassword == "" {
			return "", fmt.Errorf("failed to fetch secret %q: missing password key", secretRef)
		}
		r.logger.Debug(
			"Using TCP password from secret",
			types.SecretRefLogField, secretRef,
			types.InstanceLogField, instanceName,
			types.PeerLogField, peerName,
		)
		return tcpPassword, nil
	}
	return "", nil
}

func (r *NeighborReconciler) fetchSecret(name string) (map[string][]byte, bool, error) {
	if r.SecretStore == nil {
		return nil, false, fmt.Errorf("SecretsNamespace not configured")
	}
	item, ok, err := r.SecretStore.GetByKey(resource.Key{Namespace: r.DaemonConfig.BGPSecretsNamespace, Name: name})
	if err != nil || !ok {
		if errors.Is(err, store.ErrStoreUninitialized) {
			err = errors.Join(err, ErrAbortReconcile)
		}
		return nil, ok, err
	}
	result := map[string][]byte{}
	for k, v := range item.Data {
		result[k] = []byte(v)
	}
	return result, true, nil
}

// GetPeerAddressFromConfig returns peering address for the given peer from the provided BGPNodeInstance.
// If no error is returned and "exists" is false, it means that PeerAddress is not present in peer configuration.
func GetPeerAddressFromConfig(conf *v2.CiliumBGPNodeInstance, peerName string) (addr netip.Addr, exists bool, err error) {
	if conf == nil {
		return netip.Addr{}, false, fmt.Errorf("passed instance is nil")
	}

	for _, peer := range conf.Peers {
		if peer.Name == peerName {
			if peer.PeerAddress != nil {
				addr, err = netip.ParseAddr(*peer.PeerAddress)
				return addr, true, err
			} else {
				return netip.Addr{}, false, nil // PeerAddress not present in peer configuration
			}
		}
	}
	return netip.Addr{}, false, fmt.Errorf("peer %s not found in instance %s", peerName, conf.Name)
}

func (r *NeighborReconciler) neighborID(n *v2.CiliumBGPNodePeer) string {
	return fmt.Sprintf("%s%s%d", n.Name, *n.PeerAddress, *n.PeerASN)
}
