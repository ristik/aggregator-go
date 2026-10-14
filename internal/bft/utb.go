package bft

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/utb"
)

// utbHistoryProvider is implemented by the trust-base provider of a deployment with the signed trust-base history (record version 2).
type utbHistoryProvider interface {
	UTBHistory() *utb.History
}

// handleCertificationResponseV2 authenticates and appends the attached signed entries, catches up when they do not follow the held tip, and then
// handles the certificate exactly as a legacy response: the entries are an authority update independent of the response's status, a valid entry never
// turns a rejection into an acceptance and an invalid one never affects the certificate.
func (c *BFTClientImpl) handleCertificationResponseV2(ctx context.Context, cr *certification.CertificationResponseV2) error {
	if err := cr.IsValid(); err != nil {
		return fmt.Errorf("invalid CertificationResponseV2: %w", err)
	}
	if c.utb != nil && len(cr.TrustBaseUpdates) > 0 {
		updates := make([][]byte, len(cr.TrustBaseUpdates))
		for i, u := range cr.TrustBaseUpdates {
			updates[i] = u
		}
		added, gap, err := c.utb.Ingest(updates)
		switch {
		case err != nil:
			c.logger.WithContext(ctx).Warn("dropping an invalid trust-base update", "error", err.Error())
		case gap:
			c.logger.WithContext(ctx).Info("trust-base gap in certification response", "added", added, "tip", c.utb.Tip().Epoch)
			c.catchUpTrustBase(ctx)
		case added > 0:
			c.logger.WithContext(ctx).Info("trust-base entries appended from certification response", "added", added, "tip", c.utb.Tip().Epoch)
		}
	}
	return c.handleCertificationResponse(ctx, cr.Response())
}

// verifyUC verifies the certificate under its own epoch. With the signed history: the held entry of the seal's epoch, its strict weighted quorum and
// activation interval; an unknown epoch triggers one bounded catch-up and one retry, and nothing advances while the authority stays unknown.
func (c *BFTClientImpl) verifyUC(ctx context.Context, uc *types.UnicityCertificate) error {
	if c.utb == nil {
		tb, err := c.trustBaseStore.GetByEpoch(ctx, uc.GetRootEpoch())
		if err != nil {
			return fmt.Errorf("failed to load trust base for epoch %d: %w", uc.GetRootEpoch(), err)
		}
		return uc.Verify(tb, crypto.SHA256, c.partitionID, c.shardID, nil)
	}
	err := c.utb.VerifyUC(uc, c.partitionID, c.shardID)
	if errors.Is(err, utb.ErrUnknownEpoch) {
		c.catchUpTrustBase(ctx)
		err = c.utb.VerifyUC(uc, c.partitionID, c.shardID)
	}
	return err
}

// trustBase is the committee of an epoch, used for routing. With the signed history an unknown epoch triggers one bounded catch-up.
func (c *BFTClientImpl) trustBase(ctx context.Context, epoch uint64) (types.RootTrustBase, error) {
	if c.utb == nil {
		tb, err := c.trustBaseStore.GetByEpoch(ctx, epoch)
		if err != nil {
			return nil, fmt.Errorf("failed to load trust base for epoch %d: %w", epoch, err)
		}
		return tb, nil
	}
	e, err := c.utb.Committee(epoch)
	if errors.Is(err, utb.ErrUnknownEpoch) {
		c.catchUpTrustBase(ctx)
		e, err = c.utb.Committee(epoch)
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

// newestCommittee is the latest held entry when it is newer than epoch: its committee is added to (never substituted for) the routing targets, because a
// held future entry does not mean that committee is already the one certifying.
func (c *BFTClientImpl) newestCommittee(epoch uint64) types.RootTrustBase {
	if c.utb == nil {
		return nil
	}
	tip := c.utb.Tip().Epoch
	if tip <= epoch {
		return nil
	}
	e, err := c.utb.Committee(tip)
	if err != nil {
		return nil
	}
	return e
}

// withNewestCommittee extends the selected root peers of the certificate's epoch with the newest held committee's.
func (c *BFTClientImpl) withNewestCommittee(ids peer.IDSlice, epoch uint64, pick func(types.RootTrustBase) (peer.IDSlice, error)) peer.IDSlice {
	tb := c.newestCommittee(epoch)
	if tb == nil {
		return ids
	}
	more, err := pick(tb)
	if err != nil {
		c.logger.Warn("selecting root nodes of the newest committee", "error", err.Error())
		return ids
	}
	return unionPeers(ids, more)
}

// catchUpTrustBase fetches the missing entries after the held tip over the roots' GetTrustBase protocol (never the root HTTP endpoint), asking the
// newest held committee first and then every older one.
func (c *BFTClientImpl) catchUpTrustBase(ctx context.Context) {
	c.mu.Lock()
	self := c.peer
	c.mu.Unlock()
	if c.utb == nil {
		return
	}
	fetcher := c.trustBaseFetcher
	if fetcher == nil {
		if self == nil {
			return
		}
		fetcher = &gettrustbase.Client{Peer: self}
	}
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
	from := c.utb.Tip().Epoch + 1
	c.logger.WithContext(ctx).Info("trust-base catch-up started", "from", from, "peers", len(peers))
	added, err := c.utb.CatchUp(ctx, &loggingFetcher{f: fetcher, c: c}, peers)
	if err != nil {
		c.logger.WithContext(ctx).Warn("trust-base catch-up finished", "added", added, "tip", c.utb.Tip().Epoch, "error", err.Error())
		return
	}
	c.logger.WithContext(ctx).Info("trust-base catch-up finished", "added", added, "tip", c.utb.Tip().Epoch)
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
