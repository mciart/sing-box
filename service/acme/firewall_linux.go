//go:build with_acme && linux

package acme

import (
	"bytes"
	"sync"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	"golang.org/x/sys/unix"
)

// acmeFirewallUserData marks temporary accept rules so they can be removed
// without touching the rest of the chain. Rules are installed through netlink
// and are not written to /etc/nftables.conf.
const acmeFirewallUserData = "sing-box-acme"

// acmeFirewallTable is the previous standalone table. It is removed on cleanup
// because an accept there does not override a later filter policy of drop.
const acmeFirewallTable = "sing-box-acme"

var acmeFirewallMu sync.Mutex

func syncACMEFirewall(allows []firewallAllow) (bool, error) {
	acmeFirewallMu.Lock()
	defer acmeFirewallMu.Unlock()

	nft, err := nftables.New()
	if err != nil {
		return false, err
	}
	chains, err := nft.ListChains()
	if err != nil {
		return false, err
	}
	targets := make([]*nftables.Chain, 0, len(chains))
	for _, chain := range chains {
		if isInputFilterBaseChain(chain) {
			targets = append(targets, chain)
		}
	}
	for _, chain := range targets {
		rules, err := nft.GetRules(chain.Table, chain)
		if err != nil {
			return false, err
		}
		for _, rule := range rules {
			if bytes.Equal(rule.UserData, []byte(acmeFirewallUserData)) {
				if err := nft.DelRule(rule); err != nil {
					return false, err
				}
			}
		}
	}
	table, err := nft.ListTableOfFamily(acmeFirewallTable, nftables.TableFamilyINet)
	if err == nil && table != nil {
		nft.DelTable(table)
	}

	allows = normalizeFirewallAllows(allows)
	if len(allows) == 0 || len(targets) == 0 {
		return false, nft.Flush()
	}
	for _, allow := range allows {
		for _, chain := range targets {
			nft.InsertRule(&nftables.Rule{
				Table:    chain.Table,
				Chain:    chain,
				UserData: []byte(acmeFirewallUserData),
				Exprs:    allowExprs(allow),
			})
		}
	}
	return true, nft.Flush()
}

func closeACMEFirewall() error {
	_, err := syncACMEFirewall(nil)
	return err
}

func isInputFilterBaseChain(chain *nftables.Chain) bool {
	if chain == nil || chain.Table == nil || chain.Hooknum == nil || chain.Type != nftables.ChainTypeFilter {
		return false
	}
	switch chain.Table.Family {
	case nftables.TableFamilyINet, nftables.TableFamilyIPv4, nftables.TableFamilyIPv6:
	default:
		return false
	}
	return *chain.Hooknum == *nftables.ChainHookInput
}

func allowExprs(allow firewallAllow) []expr.Any {
	var exprs []expr.Any
	address := canonicalFirewallIP(allow.address)
	if address != nil {
		if v4 := address.To4(); v4 != nil {
			exprs = append(exprs,
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: v4},
			)
		} else {
			exprs = append(exprs,
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: address},
			)
		}
	}
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(allow.port))},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	return exprs
}
