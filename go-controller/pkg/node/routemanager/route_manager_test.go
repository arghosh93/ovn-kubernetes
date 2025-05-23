package routemanager

import (
	"net"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	utilsnet "k8s.io/utils/net"
	"k8s.io/utils/ptr"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
)

// mainTableID is the default routing table. IPRoute2 names the default routing table as 'main'
const mainTableID = 254

var _ = ginkgo.Describe("Route Manager", func() {
	defer ginkgo.GinkgoRecover()
	var rm *Controller
	var stopCh chan struct{}
	var wg *sync.WaitGroup
	var testNS ns.NetNS
	var loLink netlink.Link
	_, v4DefaultRouteIPNet, _ := net.ParseCIDR("0.0.0.0/0")
	loMTU := 65520
	loAlternativeMTU := 9000
	loLinkName := "lo"
	loSubnet := &net.IPNet{
		IP:   net.IPv4(127, 1, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}
	altSubnet := &net.IPNet{
		IP:   net.IPv4(10, 10, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}
	loIP := net.IPv4(127, 1, 1, 1)
	loIPDiff := net.IPv4(127, 1, 1, 2)
	loGWIP := net.IPv4(127, 1, 1, 254)
	customTableID := 1005
	if ovntest.NoRoot() {
		defer ginkgo.GinkgoRecover()
		ginkgo.Skip("Test requires root privileges")
	}

	ginkgo.BeforeEach(func() {
		var err error
		runtime.LockOSThread()
		testNS, err = testutils.NewNS()
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		wg = &sync.WaitGroup{}
		stopCh = make(chan struct{})
		syncPeriod := 300 * time.Millisecond
		rm = NewController()
		err = testNS.Do(func(ns.NetNS) error {
			loLink, err = netlink.LinkByName(loLinkName)
			if err != nil {
				return err
			}
			if err := netlink.LinkSetUp(loLink); err != nil {
				return err
			}

			loAddr := &netlink.Addr{
				IPNet: loSubnet,
			}
			if err := netlink.AddrAdd(loLink, loAddr); err != nil {
				return err
			}
			return nil
		})
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		wg.Add(1)
		go func() {
			defer ginkgo.GinkgoRecover()
			defer wg.Done()
			err := testNS.Do(func(ns.NetNS) error {
				rm.Run(stopCh, syncPeriod)
				return nil
			})
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		}()
	})

	ginkgo.AfterEach(func() {
		defer runtime.UnlockOSThread()
		close(stopCh)
		wg.Wait()
		gomega.Expect(testNS.Close()).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(testutils.UnmountNS(testNS)).To(gomega.Succeed())
	})

	ginkgo.Context("add route", func() {
		ginkgo.It("applies default route in custom table", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: v4DefaultRouteIPNet, Table: customTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, customTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("applies default route with gateway in custom table", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: v4DefaultRouteIPNet, Gw: loIP, Table: customTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, customTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("applies route with subnet, gateway IP, src IP, MTU", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: loSubnet, Gw: loGWIP, MTU: loMTU, Src: loIP, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("applies route with subnets, gateway IP, src IP", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Gw: loGWIP, Dst: loSubnet, Src: loIP, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("applies route with subnets, gateway IP", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Gw: loGWIP, Dst: loSubnet, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("applies route with subnets", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: loSubnet, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("route exists, has different mtu and is updated", func() {
			route := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: loSubnet, MTU: loMTU, Src: loIP, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRoute(testNS, route)).Should(gomega.Succeed())
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: loSubnet, MTU: loAlternativeMTU, Src: loIP, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("route exists, has different src and is updated", func() {
			route := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: loSubnet, Src: loIP, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRoute(testNS, route)).Should(gomega.Succeed())
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: loSubnet, Src: loIPDiff, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("two equal routes, different tables", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: loSubnet, Src: loIPDiff, Table: 5, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			validateRoute := func(testNS ns.NetNS, r netlink.Route, tableID int) func() bool {
				return func() bool {
					return isRouteInTable(testNS, r, loLink.Attrs().Index, tableID)
				}
			}
			gomega.Eventually(validateRoute(testNS, r, 5)).WithTimeout(time.Second).Should(gomega.BeTrue())
			r.Table = 6
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(validateRoute(testNS, r, 6)).WithTimeout(time.Second).Should(gomega.BeTrue())
			// delete route in table 6
			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return netlink.RouteDel(&r)
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
			// validate it is restored in table 6
			gomega.Eventually(validateRoute(testNS, r, 6), time.Second).Should(gomega.BeTrue())
		})
	})

	ginkgo.Context("del route", func() {
		ginkgo.It("del route with dst", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: altSubnet, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
			gomega.Expect(delRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeFalse())
		})

		ginkgo.It("del route with dst and gateway", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: altSubnet, Gw: loGWIP, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
			gomega.Expect(delRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeFalse())
		})

		ginkgo.It("del route with dst, gateway and MTU", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: altSubnet, Gw: loGWIP, MTU: loMTU, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
			gomega.Expect(delRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeFalse())
		})

		ginkgo.It("del route amongst multiple managed routes present", func() {
			rAlt := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: altSubnet, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, rAlt)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, rAlt, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
			rDefault := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: v4DefaultRouteIPNet, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, rDefault)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRoutesInTable(testNS, []netlink.Route{rDefault, rAlt}, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
			gomega.Expect(delRouteViaManager(rm, testNS, rAlt)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, rAlt, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeFalse())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, rDefault, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("del route and ignores unmanaged route", func() {
			rAlt := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: altSubnet, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRoute(testNS, rAlt)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, rAlt, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
			rDefault := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: v4DefaultRouteIPNet, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, rDefault)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRoutesInTable(testNS, []netlink.Route{rDefault, rAlt}, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
			gomega.Expect(delRouteViaManager(rm, testNS, rDefault)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, rAlt, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("del default route in custom route table", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: v4DefaultRouteIPNet, Table: customTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, customTableID)
			}, time.Second).Should(gomega.BeTrue())
		})
	})

	ginkgo.Context("runtime sync", func() {
		ginkgo.It("reapplies managed route that was removed (gw IP, mtu, src IP)", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Gw: loGWIP, Dst: loSubnet, MTU: loMTU, Src: loIP, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
			// clear routes and wait for sync to reapply
			routeList, err := getRouteList(testNS, loLink, netlink.FAMILY_ALL)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			gomega.Expect(routeList).ShouldNot(gomega.BeEmpty())
			gomega.Expect(deleteRoutes(testNS, routeList...)).ShouldNot(gomega.HaveOccurred())
			// wait for sync to activate since managed routes have been deleted
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("reapplies managed route that was removed (mtu, src IP)", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: loSubnet, MTU: loMTU, Src: loIP, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
			// clear routes and wait for sync to reapply
			routeList, err := getRouteList(testNS, loLink, netlink.FAMILY_ALL)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			gomega.Expect(routeList).ShouldNot(gomega.BeEmpty())
			gomega.Expect(deleteRoutes(testNS, routeList...)).ShouldNot(gomega.HaveOccurred())
			// wait for sync to activate since managed routes have been deleted
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("reapplies managed route that was removed because link is down", func() {
			r := netlink.Route{LinkIndex: loLink.Attrs().Index, Dst: loSubnet, MTU: loMTU, Src: loIP, Table: mainTableID, Type: unix.RTN_UNICAST}
			gomega.Expect(addRouteViaManager(rm, testNS, r)).Should(gomega.Succeed())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
			gomega.Expect(setLinkDown(testNS, loLink)).ShouldNot(gomega.HaveOccurred())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeFalse())
			gomega.Expect(setLinkUp(testNS, loLink)).ShouldNot(gomega.HaveOccurred())
			gomega.Eventually(func() bool {
				return isRouteInTable(testNS, r, loLink.Attrs().Index, mainTableID)
			}, time.Second).Should(gomega.BeTrue())
		})

		ginkgo.It("deleting link doesn't cause panic", func() {
			var link netlink.Link
			var err error
			mac, _ := net.ParseMAC("00:00:5e:00:53:44")
			dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
				Index:        99,
				MTU:          1500,
				Name:         "dummy",
				HardwareAddr: mac,
			}}
			gomega.Expect(testNS.Do(func(ns.NetNS) error {
				if err := netlink.LinkAdd(dummy); err != nil {
					return err
				}
				if link, err = netlink.LinkByName("dummy"); err != nil {
					return err
				}
				if err = netlink.LinkSetUp(link); err != nil {
					return err
				}
				r := netlink.Route{LinkIndex: link.Attrs().Index, Dst: v4DefaultRouteIPNet, Table: mainTableID, Type: unix.RTN_UNICAST}
				if err = rm.Add(r); err != nil {
					return err
				}
				return netlink.LinkDel(link)
			})).Should(gomega.Succeed())
			time.Sleep(400 * time.Millisecond) // sync period is 300 ms
		})
	})
})

var _ = ginkgo.Describe("Route Manager", func() {
	ginkgo.It("partially compares expected routes with installed routes", func() {
		values := map[string]any{
			"int":           1,
			"Scope":         uint8(1),
			"IPNet":         ovntest.MustParseIPNet("10.0.0.0/16"),
			"IP":            ovntest.MustParseIP("10.0.0.0"),
			"NexthopInfo":   []*netlink.NexthopInfo{{LinkIndex: 1}},
			"RouteProtocol": 1,
			"*int":          ptr.To(1),
			"Destination":   &netlink.Via{Addr: ovntest.MustParseIP("10.0.0.0")},
			"Encap":         &netlink.IP6tnlEncap{Src: ovntest.MustParseIP("10.0.0.0")},
			"string":        "test",
		}
		keys := map[string]bool{
			"Dst":      true,
			"Priority": true,
			"Table":    true,
		}

		var getName func(reflect.Type, string) string
		getName = func(t reflect.Type, prefix string) string {
			name := prefix + t.Name()
			_, known := values[name]
			if known {
				return name
			}
			kind := t.Kind()
			switch kind {
			case reflect.Pointer:
				return getName(t.Elem(), "*")
			case reflect.Slice:
				return getName(t.Elem(), "[]")
			default:
				return t.Name()
			}
		}

		// we iterate all the fields of a Route and test that:
		// - correctly detects differences of non zero left values against zero right values
		// - correctly detects differences of zero left values against non zero right values if key
		// - correctly ignores differences of zero left values against non zero right values if not key
		var z netlink.Route
		zv := reflect.ValueOf(z)
		for i := 0; i < zv.NumField(); i++ {
			var t netlink.Route
			tv := reflect.ValueOf(&t).Elem()
			fv := tv.Field(i)
			ft := fv.Type()
			fn := tv.Type().Field(i).Name

			ftn := getName(ft, "")

			gomega.Expect(values).To(gomega.HaveKey(ftn), "unexpected field %q of type %s", fn, ftn)

			fv.Set(reflect.ValueOf(values[ftn]).Convert(ft))

			isKey := keys[fn]
			gomega.Expect(routePartiallyEqualWantedToExisting(&t, &z)).To(gomega.BeFalse(), "differences of non zero left values against zero right values not detected for field %s", fn)
			gomega.Expect(routePartiallyEqualWantedToExisting(&z, &t)).ToNot(gomega.Equal(isKey), "differences of zero left values against non zero right values not ignored (or detected if field is key) for field %s", fn)
		}
	})
})

func addRouteViaManager(rm *Controller, targetNS ns.NetNS, r netlink.Route) error {
	return targetNS.Do(func(ns.NetNS) error { return rm.Add(r) })
}
func delRouteViaManager(rm *Controller, targetNS ns.NetNS, r netlink.Route) error {
	return targetNS.Do(func(ns.NetNS) error { return rm.Del(r) })
}

func addRoute(targetNS ns.NetNS, r netlink.Route) error {
	return targetNS.Do(func(ns.NetNS) error {
		return netlink.RouteAdd(&r)
	})
}

// isRouteInTable ensure only the expected route for a link are within a table
func isRouteInTable(targetNs ns.NetNS, expectedRoute netlink.Route, linkIndex, table int) bool {
	return isRoutesInTable(targetNs, []netlink.Route{expectedRoute}, linkIndex, table)
}

func filterRouteByTable(linkIndex, table int) (*netlink.Route, uint64) {
	return &netlink.Route{
			LinkIndex: linkIndex,
			Table:     table,
		},
		netlink.RT_FILTER_OIF | netlink.RT_FILTER_TABLE
}

// isRoutesInTable ensures only the slice of expected routes for a link are present within a table
func isRoutesInTable(targetNs ns.NetNS, expectedRoutes []netlink.Route, linkIndex, table int) bool {
	if len(expectedRoutes) == 0 {
		panic("expect at least one route")
	}
	existingRoutes := make([]netlink.Route, 0)
	var err error
	err = targetNs.Do(func(ns.NetNS) error {
		filter, mask := filterRouteByTable(linkIndex, table)
		existingRoutes, err = netlink.RouteListFiltered(getIPFamily(expectedRoutes[0].Dst.IP), filter, mask)
		return err
	})
	if err != nil {
		panic(err.Error())
	}
	if len(existingRoutes) != len(expectedRoutes) {
		return false
	}
	var found bool
	for _, expectedRoute := range expectedRoutes {
		found = false
		for _, existingRoute := range existingRoutes {
			if routePartiallyEqualWantedToExisting(&expectedRoute, &existingRoute) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func getRouteList(targetNs ns.NetNS, link netlink.Link, ipFamily int) ([]netlink.Route, error) {
	routesFound := make([]netlink.Route, 0)
	var err error
	err = targetNs.Do(func(ns.NetNS) error {
		routesFound, err = netlink.RouteList(link, ipFamily)
		if err != nil {
			return err
		}
		return nil
	})
	return routesFound, err
}

func deleteRoutes(targetNs ns.NetNS, routes ...netlink.Route) error {
	var err error
	err = targetNs.Do(func(ns.NetNS) error {
		for _, route := range routes {
			if err = netlink.RouteDel(&route); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func setLinkUp(targetNS ns.NetNS, link netlink.Link) error {
	return setLink(targetNS, link, netlink.LinkSetUp)
}

func setLinkDown(targetNS ns.NetNS, link netlink.Link) error {
	return setLink(targetNS, link, netlink.LinkSetDown)
}
func setLink(targetNS ns.NetNS, link netlink.Link, nlFunc func(link2 netlink.Link) error) error {
	err := targetNS.Do(func(ns.NetNS) error {
		if err := nlFunc(link); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func getIPFamily(ip net.IP) int {
	if len(ip) == 0 {
		panic("getIPFamily(): nil IP passed as argument")
	}
	if utilsnet.IsIPv6(ip) {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}
