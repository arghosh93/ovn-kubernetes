// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package iprulemanager

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	ovntest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing"
)

// FIXME(mk) - Within GH VM, if I need to create a new NetNs. I see the following error:
// "failed to create new network namespace: mount --make-rshared /run/user/1001/netns failed: "operation not permitted""
var _ = ginkgo.XDescribe("IP Rule Manager", func() {
	var stopCh chan struct{}
	var wg *sync.WaitGroup
	var testNS ns.NetNS
	var c *Controller
	var _, testIPNet, _ = net.ParseCIDR("192.168.1.5/24")
	ruleWithDst := netlink.NewRule()
	ruleWithDst.Priority = 3000
	ruleWithDst.Table = 254
	ruleWithDst.Dst = testIPNet
	ruleWithSrc := netlink.NewRule()
	ruleWithSrc.Priority = 3000
	ruleWithSrc.Table = 254
	ruleWithSrc.Src = testIPNet

	defer ginkgo.GinkgoRecover()
	if ovntest.NoRoot() {
		ginkgo.Skip("Test requires root privileges")
	}

	ginkgo.BeforeEach(func() {
		var err error
		runtime.LockOSThread()
		testNS, err = testutils.NewNS()
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		wg = &sync.WaitGroup{}
		stopCh = make(chan struct{})
		wg.Add(1)
		c = NewController(true, true)
		go func() {
			defer ginkgo.GinkgoRecover()
			defer wg.Done()
			err := testNS.Do(func(ns.NetNS) error {
				c.Run(stopCh, time.Millisecond*50)
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

	ginkgo.Context("Add rule", func() {
		ginkgo.It("ensure rule exist", func() {
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.Add(*ruleWithDst)
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					rules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(rules, ruleWithDst); !ok {
						return fmt.Errorf("failed to find rule %q", ruleWithDst.String())
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
		})

		ginkgo.It("ensure rule is restored if it is removed", func() {
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.Add(*ruleWithDst)
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					rules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(rules, ruleWithDst); !ok {
						return fmt.Errorf("failed to find rule %q", ruleWithDst.String())
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return netlink.RuleDel(ruleWithDst)
				})
			}()).Should(gomega.Succeed())
			// check that rule is restored
			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					rules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(rules, ruleWithDst); !ok {
						return fmt.Errorf("failed to find rule %q", ruleWithDst.String())
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
		})

		ginkgo.It("ensure multiple rules are restored if they're removed", func() {
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.Add(*ruleWithDst)
				})
			}()).Should(gomega.Succeed())
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.Add(*ruleWithSrc)
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					rules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(rules, ruleWithDst); !ok {
						return fmt.Errorf("failed to find rule with dst")
					}
					if ok2, _ := isNetlinkRuleInSlice(rules, ruleWithSrc); !ok2 {
						return fmt.Errorf("failed to find rule with src")
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return netlink.RuleDel(ruleWithDst)
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					rules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(rules, ruleWithDst); !ok {
						return fmt.Errorf("failed to find rule %s", ruleWithDst.String())
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return netlink.RuleDel(ruleWithSrc)
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					rules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(rules, ruleWithSrc); !ok {
						return fmt.Errorf("failed to find rule %s", ruleWithSrc)
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
		})
	})

	ginkgo.Context("Del rule", func() {
		ginkgo.It("doesn't fail when no rule to delete", func() {
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.Delete(*ruleWithDst)
				})
			}()).Should(gomega.Succeed())
		})

		ginkgo.It("deletes a rule", func() {
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					if err := c.Add(*ruleWithDst); err != nil {
						return err
					}
					if err := c.Delete(*ruleWithDst); err != nil {
						return err
					}
					return nil
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					rules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(rules, ruleWithDst); ok {
						return fmt.Errorf("expected rule (%s) to be deleted but it was found", ruleWithDst)
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
		})
	})

	ginkgo.Context("AddRules batch", func() {
		ginkgo.It("ensure multiple rules exist when added in batch", func() {
			var _, testIPNet2, _ = net.ParseCIDR("192.168.2.5/24")
			var _, testIPNet3, _ = net.ParseCIDR("192.168.3.5/24")

			ruleWithDst2 := netlink.NewRule()
			ruleWithDst2.Priority = 3001
			ruleWithDst2.Table = 254
			ruleWithDst2.Dst = testIPNet2

			ruleWithDst3 := netlink.NewRule()
			ruleWithDst3.Priority = 3002
			ruleWithDst3.Table = 254
			ruleWithDst3.Dst = testIPNet3

			rules := []netlink.Rule{*ruleWithDst, *ruleWithDst2, *ruleWithDst3}

			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.AddRules(rules)
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					existingRules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(existingRules, ruleWithDst); !ok {
						return fmt.Errorf("failed to find rule %q", ruleWithDst.String())
					}
					if ok, _ := isNetlinkRuleInSlice(existingRules, ruleWithDst2); !ok {
						return fmt.Errorf("failed to find rule %q", ruleWithDst2.String())
					}
					if ok, _ := isNetlinkRuleInSlice(existingRules, ruleWithDst3); !ok {
						return fmt.Errorf("failed to find rule %q", ruleWithDst3.String())
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
		})

		ginkgo.It("handles empty slice without error", func() {
			rules := []netlink.Rule{}
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.AddRules(rules)
				})
			}()).Should(gomega.Succeed())
		})

		ginkgo.It("deduplicates when adding same rule multiple times in batch", func() {
			rules := []netlink.Rule{*ruleWithDst, *ruleWithDst}

			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.AddRules(rules)
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					existingRules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					// Count how many times the rule appears
					count := 0
					for _, r := range existingRules {
						if areNetlinkRulesEqual(&r, ruleWithDst) {
							count++
						}
					}
					if count != 1 {
						return fmt.Errorf("expected rule to appear once, but found %d times", count)
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
		})

		ginkgo.It("deduplicates when rule already managed via Add()", func() {
			// Add one rule via Add()
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.Add(*ruleWithDst)
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					rules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(rules, ruleWithDst); !ok {
						return fmt.Errorf("failed to find rule %q", ruleWithDst.String())
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())

			// Now add the same rule via AddRules()
			rules := []netlink.Rule{*ruleWithDst, *ruleWithSrc}
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.AddRules(rules)
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					existingRules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					// Both rules should exist
					if ok, _ := isNetlinkRuleInSlice(existingRules, ruleWithDst); !ok {
						return fmt.Errorf("failed to find rule with dst")
					}
					if ok, _ := isNetlinkRuleInSlice(existingRules, ruleWithSrc); !ok {
						return fmt.Errorf("failed to find rule with src")
					}
					// Check ruleWithDst appears only once
					count := 0
					for _, r := range existingRules {
						if areNetlinkRulesEqual(&r, ruleWithDst) {
							count++
						}
					}
					if count != 1 {
						return fmt.Errorf("expected ruleWithDst to appear once, but found %d times", count)
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
		})

		ginkgo.It("ensure batch-added rules are restored if removed", func() {
			var _, testIPNet2, _ = net.ParseCIDR("192.168.2.5/24")
			ruleWithDst2 := netlink.NewRule()
			ruleWithDst2.Priority = 3001
			ruleWithDst2.Table = 254
			ruleWithDst2.Dst = testIPNet2

			rules := []netlink.Rule{*ruleWithDst, *ruleWithDst2}

			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return c.AddRules(rules)
				})
			}()).Should(gomega.Succeed())

			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					existingRules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(existingRules, ruleWithDst); !ok {
						return fmt.Errorf("failed to find rule %q", ruleWithDst.String())
					}
					if ok, _ := isNetlinkRuleInSlice(existingRules, ruleWithDst2); !ok {
						return fmt.Errorf("failed to find rule %q", ruleWithDst2.String())
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())

			// Delete one of the batch-added rules
			gomega.Expect(func() error {
				return testNS.Do(func(ns.NetNS) error {
					return netlink.RuleDel(ruleWithDst)
				})
			}()).Should(gomega.Succeed())

			// Check that rule is restored by the controller
			gomega.Eventually(func() error {
				return testNS.Do(func(ns.NetNS) error {
					existingRules, err := netlink.RuleList(netlink.FAMILY_ALL)
					if err != nil {
						return err
					}
					if ok, _ := isNetlinkRuleInSlice(existingRules, ruleWithDst); !ok {
						return fmt.Errorf("failed to find restored rule %q", ruleWithDst.String())
					}
					return nil
				})
			}).WithTimeout(time.Second).Should(gomega.Succeed())
		})
	})
})
