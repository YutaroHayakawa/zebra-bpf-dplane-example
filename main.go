// SPDX-License-Identifier: Apache-2.0
// Copyright Yutaro Hayakawa

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-Wno-int-conversion -DBPF_NO_GLOBAL_DATA" ingress bpf/tc-ingress.bpf.c

func syncVrfTable2Ifindex(m *ebpf.Map, ctx context.Context) {
	updateCh := make(chan netlink.LinkUpdate)

	opt := netlink.LinkSubscribeOptions{
		ListExisting: true,
	}

	if err := netlink.LinkSubscribeWithOptions(updateCh, ctx.Done(), opt); err != nil {
		panic(err)
	}

	for update := range updateCh {
		vrf, ok := update.Link.(*netlink.Vrf)
		if !ok {
			continue
		}

		// Sync VRF Table ID => VRF Ifindex mapping
		switch update.Header.Type {
		case unix.RTM_NEWLINK:
			log.Printf("VRF Update: %s (table: %d, ifindex: %d)",
				vrf.Name, vrf.Table, vrf.Index)

			if err := m.Update(uint32(vrf.Table), uint32(vrf.Index), 0); err != nil {
				panic(err)
			}
		case unix.RTM_DELLINK:
			log.Printf("VRF Delete: %s (table: %d, ifindex: %d)",
				vrf.Name, vrf.Table, vrf.Index)

			if err := m.Delete(uint32(vrf.Table)); err != nil {
				panic(err)
			}
		}
	}
}

func attachTCIngress(link netlink.Link, prog *ebpf.Program) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscReplace(qdisc); err != nil {
		return err
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("failed to replace tc ingress: %w", err)
	}

	log.Printf("Attached TC Qdisc and BPF program to %s", link.Attrs().Name)

	return nil
}

func main() {
	if len(os.Args) == 1 {
		fmt.Printf("Usage: %s <iface0> <iface1> ...\n", os.Args[0])
		return
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := ingressObjects{}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction | ebpf.LogLevelStats,
			LogSize:  0xffff,
		},
	}

	if err := loadIngressObjects(&objs, &opts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			for _, s := range verr.Log {
				log.Println(s)
			}
		}
		panic(err)
	}

	defer objs.Close()

	for _, arg := range os.Args[1:] {
		link, err := netlink.LinkByName(arg)
		if err != nil {
			panic(err)
		}

		if err := attachTCIngress(link, objs.IngressMain); err != nil {
			panic(err)
		}
	}

	syncVrfTable2Ifindex(objs.Vrftable2ifindex, context.TODO())
}
