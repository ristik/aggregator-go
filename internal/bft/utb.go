package bft

import (
	"context"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/storage/interfaces"
	"github.com/unicitynetwork/aggregator-go/internal/utb"
)

// utbHistoryProvider is implemented by the trust-base provider of a deployment with the signed trust-base history (record version 2).
type utbHistoryProvider interface {
	UTBHistory() *utb.History
}

// ErrNextEpochNotFetched: the roots did not serve the entry after the held tip.
var ErrNextEpochNotFetched = errors.New("the next trust-base entry could not be fetched")

// utbAuthority makes the held history the authority source of the shared UC authenticator: local reads of held entries only.
type utbAuthority struct{ h *utb.History }

func (a utbAuthority) GetAdmittedAuthority(_ context.Context, epoch uint64) (types.RootTrustBase, bool, error) {
	e, err := a.h.Committee(epoch)
	if errors.Is(err, utb.ErrUnknownEpoch) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return e, true, nil
}

// utbIntake is the intake view of the held history: the admitted root peer set derives from it and the single catch-up worker extends it, by peer
// GetTrustBase from the held tip, never by root HTTP and never from an epoch advertised by a message.
type utbIntake struct{ c *BFTClientImpl }

func (i utbIntake) GetByEpochLocal(_ context.Context, epoch uint64) (types.RootTrustBase, error) {
	e, err := i.c.utb.Committee(epoch)
	if errors.Is(err, utb.ErrUnknownEpoch) {
		return nil, interfaces.ErrTrustBaseNotFound
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (i utbIntake) Head(context.Context) (uint64, error) { return i.c.utb.Tip().Epoch, nil }

// AdmitNext fetches the entry after the held tip from the roots (newest held committee first), authenticated by the store from the tip.
func (i utbIntake) AdmitNext(ctx context.Context) (uint64, error) {
	c := i.c
	next := c.utb.Tip().Epoch + 1
	fetcher, peers := c.utbFetcher(), c.utbPeers()
	if fetcher == nil || len(peers) == 0 {
		return 0, fmt.Errorf("%w: no peer to ask", ErrNextEpochNotFetched)
	}
	c.logger.WithContext(ctx).Info("trust-base catch-up started", "from", next, "peers", len(peers))
	added, err := c.utb.CatchUpTo(ctx, &loggingFetcher{f: fetcher, c: c}, peers, next)
	tip := c.utb.Tip().Epoch
	if err != nil {
		c.logger.WithContext(ctx).Warn("trust-base catch-up finished", "added", added, "tip", tip, "error", err.Error())
	} else {
		c.logger.WithContext(ctx).Info("trust-base catch-up finished", "added", added, "tip", tip)
	}
	if tip < next {
		if err == nil {
			err = errors.New("no root served it")
		}
		return 0, fmt.Errorf("%w: epoch %d: %w", ErrNextEpochNotFetched, next, err)
	}
	return next, nil
}

// utbFetcher is the GetTrustBase client on this node's libp2p peer (or the injected one).
func (c *BFTClientImpl) utbFetcher() gettrustbase.Fetcher {
	if c.trustBaseFetcher != nil {
		return c.trustBaseFetcher
	}
	c.mu.Lock()
	self := c.peer
	c.mu.Unlock()
	if self == nil {
		return nil
	}
	return &gettrustbase.Client{Peer: self}
}

// utbPeers are the roots of the newest held committee first, then of every older one.
func (c *BFTClientImpl) utbPeers() peer.IDSlice {
	var peers peer.IDSlice
	for epoch := c.utb.Tip().Epoch; ; epoch-- {
		e, err := c.utb.Committee(epoch)
		if err != nil {
			break
		}
		if ids, err := rootNodesIDSlice(e); err == nil {
			peers = unionPeers(peers, ids)
		}
		if epoch == 0 {
			break
		}
	}
	return peers
}

// noteAdmitted records that the history now holds the epoch: the admitted head and the admitted root peer set follow it.
func (c *BFTClientImpl) noteAdmitted(ctx context.Context, epoch uint64) {
	for cur := c.admittedHead.Load(); epoch > cur && !c.admittedHead.CompareAndSwap(cur, epoch); cur = c.admittedHead.Load() {
	}
	c.refreshMembership(ctx)
}

// handleCombinedResponse appends the attached signed entries and then handles the response exactly as a legacy one: the entries are an authority update
// independent of the status, a valid entry never turns a rejection into an acceptance and an invalid one never affects the certificate. A gap only wakes
// the catch-up worker (coalesced); the message path never fetches.
func (c *BFTClientImpl) handleCombinedResponse(ctx context.Context, cr *certification.CertificationResponse, updates [][]byte) error {
	c.ensureIntake()
	if c.utb != nil && len(updates) > 0 {
		added, gap, err := c.utb.Ingest(updates)
		switch {
		case err != nil:
			c.logger.WithContext(ctx).Warn("dropping an invalid trust-base update", "error", err.Error())
		case gap:
			c.logger.WithContext(ctx).Info("trust-base gap in certification response", "added", added, "tip", c.utb.Tip().Epoch)
			c.catchup.Signal()
		case added > 0:
			c.logger.WithContext(ctx).Info("trust-base entries appended from certification response", "added", added, "tip", c.utb.Tip().Epoch)
		default:
			// every attached entry was already held (the catch-up worker, or an earlier response, got there first): the attachment was read and checked, and added nothing
			c.logger.WithContext(ctx).Debug("trust-base update already held", "attached", len(updates), "tip", c.utb.Tip().Epoch)
		}
		if added > 0 {
			c.noteAdmitted(ctx, c.utb.Tip().Epoch)
		}
	}
	return c.handleCertificationResponse(ctx, cr)
}

// handshakeAuthority is the committee a handshake is addressed to. With the signed history, a last certificate whose epoch is not held (a restart with a
// fresh store) greets the newest held committee instead of failing: a handshake is only routing and grants no authority.
func (c *BFTClientImpl) handshakeAuthority(ctx context.Context, rootEpoch uint64) (types.RootTrustBase, error) {
	tb, err := c.authn.trustBase(ctx, rootEpoch)
	if c.utb != nil && errors.Is(err, ErrEpochNotAdmitted) {
		tip := c.utb.Tip().Epoch
		c.logger.WithContext(ctx).Info("trust-base handshake to the newest held committee", "certificateEpoch", rootEpoch, "tip", tip)
		c.catchup.Signal()
		return c.authn.trustBase(ctx, tip)
	}
	return tb, err
}

// withNewestCommittee extends the selected root peers with the newest held committee's, when that epoch is newer than the certificate's: a held future
// entry does not mean that committee is already the one certifying, so it is added, never substituted.
func (c *BFTClientImpl) withNewestCommittee(ids peer.IDSlice, epoch uint64, pick func(types.RootTrustBase) (peer.IDSlice, error)) peer.IDSlice {
	if c.utb == nil {
		return ids
	}
	tip := c.utb.Tip().Epoch
	if tip <= epoch {
		return ids
	}
	e, err := c.utb.Committee(tip)
	if err != nil {
		return ids
	}
	more, err := pick(e)
	if err != nil {
		c.logger.Warn("selecting root nodes of the newest committee", "error", err.Error())
		return ids
	}
	return unionPeers(ids, more)
}

// loggingFetcher records every GetTrustBase page: which root served what.
type loggingFetcher struct {
	f gettrustbase.Fetcher
	c *BFTClientImpl
}

func (l *loggingFetcher) Page(ctx context.Context, id peer.ID, req *gettrustbase.Request) (*gettrustbase.Response, [][]byte, error) {
	resp, entries, err := l.f.Page(ctx, id, req)
	if err != nil {
		l.c.logger.WithContext(ctx).Warn("trust-base catch-up page failed", "peer", id.String(), "from", req.FromEpoch, "error", err.Error())
		return resp, entries, err
	}
	next := uint64(0)
	if resp.NextEpoch != nil {
		next = *resp.NextEpoch
	}
	l.c.logger.WithContext(ctx).Info("trust-base catch-up page", "peer", id.String(), "from", req.FromEpoch, "status", resp.Status.String(),
		"entries", len(entries), "effectiveEnd", resp.EffectiveEnd, "nextEpoch", next)
	return resp, entries, err
}

func randomPicker(n int) func(types.RootTrustBase) (peer.IDSlice, error) {
	return func(tb types.RootTrustBase) (peer.IDSlice, error) { return randomNodeSelector(tb, n) }
}

func ucPicker(luc *types.UnicityCertificate, n int) func(types.RootTrustBase) (peer.IDSlice, error) {
	return func(tb types.RootTrustBase) (peer.IDSlice, error) { return rootNodesSelector(luc, tb, n) }
}

func unionPeers(a, b peer.IDSlice) peer.IDSlice {
	out := append(peer.IDSlice(nil), a...)
	for _, id := range b {
		dup := false
		for _, have := range out {
			if have == id {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, id)
		}
	}
	return out
}
