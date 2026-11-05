package utb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/storage/interfaces"
)

// ErrAuthority is the history disagreeing with the aggregator's own V1 trust base.
var ErrAuthority = errors.New("trust-base history disagrees with the aggregator's trust base")

// CheckAuthority compares the history with a V1 trust base of the aggregator on the fields both records carry: network, epoch, start round, members
// (node id, key, stake) and quorum threshold. V1 hashes are not compared with V2 entry ids (they are different identities). The V1 epoch must be
// covered by the history.
func (h *History) CheckAuthority(v1 *types.RootTrustBaseV1) error {
	if v1.GetNetworkID() != h.network {
		return fmt.Errorf("%w: V1 trust base is of network %d, the history of %d", ErrAuthority, v1.GetNetworkID(), h.network)
	}
	e := h.Entry(v1.GetEpoch())
	if e == nil {
		tip, _ := h.Tip()
		return fmt.Errorf("%w: V1 epoch %d is outside the history (epochs %d..%d)", ErrAuthority, v1.GetEpoch(), h.genesis, tip)
	}
	if e.EpochStart != v1.GetEpochStart() {
		return fmt.Errorf("%w: epoch %d starts at round %d in V1 and %d in the history", ErrAuthority, e.Epoch, v1.GetEpochStart(), e.EpochStart)
	}
	if e.QuorumThreshold != v1.GetQuorumThreshold() {
		return fmt.Errorf("%w: epoch %d quorum threshold %d in V1 and %d in the history", ErrAuthority, e.Epoch, v1.GetQuorumThreshold(), e.QuorumThreshold)
	}
	have := v1.GetRootNodes()
	if len(have) != len(e.RootNodes) {
		return fmt.Errorf("%w: epoch %d has %d members in V1 and %d in the history", ErrAuthority, e.Epoch, len(have), len(e.RootNodes))
	}
	byID := make(map[string]*types.NodeInfo, len(e.RootNodes))
	for _, n := range e.RootNodes {
		byID[n.NodeID] = n
	}
	for _, n := range have {
		m := byID[n.NodeID]
		if m == nil || !bytes.Equal(m.SigKey, n.SigKey) || m.Stake != n.Stake {
			return fmt.Errorf("%w: epoch %d member %q differs (key or stake)", ErrAuthority, e.Epoch, n.NodeID)
		}
	}
	return nil
}

// LatestV1 returns the aggregator's latest V1 trust base; interfaces.ErrTrustBaseNotFound means none is installed yet.
type LatestV1 func(ctx context.Context) (*types.RootTrustBaseV1, error)

// Guard keeps the served history consistent with the aggregator's mutable V1 trust base (which `PUT` and the BFT admission can extend while the V2
// file cannot). It re-checks when the V1 head epoch changes. While the check fails the history must not be served and readiness is degraded; it
// never repairs anything. An empty V1 store is consistent (nothing to contradict yet).
type Guard struct {
	history *History
	latest  LatestV1

	mu      sync.Mutex
	checked bool
	epoch   uint64 // V1 head epoch of the last completed check
	err     error  // its outcome
}

// NewGuard returns a guard for h over the V1 source.
func NewGuard(h *History, latest LatestV1) *Guard { return &Guard{history: h, latest: latest} }

// History is the guarded history.
func (g *Guard) History() *History { return g.history }

// Check returns nil when the history may be served. A transient failure to read V1 is returned without being remembered.
func (g *Guard) Check(ctx context.Context) error {
	v1, err := g.latest(ctx)
	if errors.Is(err, interfaces.ErrTrustBaseNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading the aggregator's latest trust base: %w", err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.checked && g.epoch == v1.GetEpoch() {
		return g.err
	}
	g.checked, g.epoch, g.err = true, v1.GetEpoch(), g.history.CheckAuthority(v1)
	return g.err
}

// CheckInstalled is the startup check: every installed V1 trust base of an epoch the history covers must agree with it, and the latest one (the active
// authority) must be covered. V1 epochs below the history's genesis are not contradicted by it and are skipped. A V1 gap is not an error here.
func (g *Guard) CheckInstalled(ctx context.Context, list func(ctx context.Context, from, to uint64) ([]*types.RootTrustBaseV1, error)) error {
	if err := g.Check(ctx); err != nil {
		return err
	}
	head, err := g.latest(ctx)
	if errors.Is(err, interfaces.ErrTrustBaseNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading the aggregator's latest trust base: %w", err)
	}
	all, err := list(ctx, g.history.GenesisEpoch(), head.GetEpoch())
	if err != nil {
		return fmt.Errorf("reading the aggregator's trust bases: %w", err)
	}
	for _, v1 := range all {
		if g.history.Entry(v1.GetEpoch()) == nil {
			continue
		}
		if err := g.history.CheckAuthority(v1); err != nil {
			return err
		}
	}
	return nil
}
