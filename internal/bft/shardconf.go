package bft

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"
)

// Following the shard's configuration across a live change (validator-registry kinds 6 ReplaceAggregatorValidators and 8 UpdatePartition).
//
// A change replaces the shard's PartitionDescriptionRecord at an activation round: the root certifies the successor's hash in every
// certificate of the new shard epoch, so a client that pins the hash of the configuration it started with would refuse them all. The
// authority for a successor is the root seal itself: the shard configuration hash is part of what the seal signs, so a certificate that
// authenticates and commits to a hash this client does not know yet is the root quorum's statement of the configuration now in force. The
// client then fetches the configuration of the next shard epoch(s) from a root, requires it to hash to exactly that sealed value and to be
// a successor of the configuration it holds (same network, partition and shard, a later epoch), and only then adopts it. Nothing a root
// serves without that hash and seal is trusted, and a certificate is never accepted on an unauthenticated hash.
//
// Certificates that commit to an earlier configuration of this shard (historical ones) keep verifying against it: every configuration
// adopted stays in the history.

// ShardConfSource serves the configuration of a shard epoch (a root's POST /api/v1/q3/shard-conf). Its answer is untrusted: the client
// checks it against the sealed hash.
type ShardConfSource interface {
	ShardConfig(ctx context.Context, partition types.PartitionID, epoch uint64) (*types.PartitionDescriptionRecord, error)
}

// maxConfLookahead bounds how many shard epochs ahead of the newest configuration held a sealed hash is searched for (a client that was
// down across several changes catches up in one step).
const maxConfLookahead = 16

// ErrShardConfUnknown reports a certificate whose sealed configuration hash is not one this client holds and cannot be followed.
var ErrShardConfUnknown = errors.New("unknown shard configuration")

type confEntry struct {
	epoch uint64
	hash  []byte
}

// shardConfFollower adopts successor configurations of the shard (see above).
type shardConfFollower struct {
	source  ShardConfSource
	onAdopt func(previous, adopted []byte) // the pins derived from the configuration hash (the consolidation topology) follow it

	mu      sync.Mutex // serialises adoption
	current *types.PartitionDescriptionRecord
}

// newShardConfFollower follows from the configuration the client started with.
func newShardConfFollower(source ShardConfSource, start *types.PartitionDescriptionRecord) *shardConfFollower {
	return &shardConfFollower{source: source, current: start}
}

// currentConfHash is the hash of the newest configuration held (nil: unchecked).
func (a *ucAuthenticator) currentConfHash() []byte {
	a.confMu.RLock()
	defer a.confMu.RUnlock()
	return a.shardConfHash
}

// knownConfHash reports whether h is the hash of a configuration of the history.
func (a *ucAuthenticator) knownConfHash(h []byte) bool {
	a.confMu.RLock()
	defer a.confMu.RUnlock()
	for _, e := range a.confs {
		if bytes.Equal(e.hash, h) {
			return true
		}
	}
	return false
}

// withShardConfFollower makes the authenticator follow the shard's configuration; start is the configuration it holds.
func (a *ucAuthenticator) withShardConfFollower(f *shardConfFollower, h []byte) *ucAuthenticator {
	a.withShardConfHash(h)
	a.confMu.Lock()
	if f != nil && f.current != nil {
		a.confs[0].epoch = f.current.Epoch
	}
	a.follow = f
	a.confMu.Unlock()
	return a
}

// adoptConf adopts the configuration whose hash the root seal committed to, from the next shard epochs. The caller has authenticated the
// certificate (shape, network and seal) already.
func (a *ucAuthenticator) adoptConf(ctx context.Context, sealed []byte) error {
	f := a.follow
	f.mu.Lock()
	defer f.mu.Unlock()
	if a.knownConfHash(sealed) { // another certificate adopted it meanwhile
		return nil
	}
	cur := f.current
	for epoch := cur.Epoch + 1; epoch <= cur.Epoch+maxConfLookahead && epoch > cur.Epoch; epoch++ {
		pdr, err := f.source.ShardConfig(ctx, cur.PartitionID, epoch)
		if err != nil || pdr == nil {
			if err != nil {
				return fmt.Errorf("%w: the certificate commits to configuration %X and epoch %d of the shard could not be fetched: %w", ErrShardConfUnknown, sealed, epoch, err)
			}
			return fmt.Errorf("%w: the certificate commits to configuration %X and no epoch %d is served", ErrShardConfUnknown, sealed, epoch)
		}
		h, err := pdr.Hash(crypto.SHA256)
		if err != nil || pdr.Epoch != epoch || pdr.NetworkID != cur.NetworkID || pdr.PartitionID != cur.PartitionID || !pdr.ShardID.Equal(cur.ShardID) {
			return fmt.Errorf("%w: the configuration served for epoch %d is not a configuration of this shard", ErrShardConfUnknown, epoch)
		}
		if !bytes.Equal(h, sealed) {
			continue // an intermediate epoch: the history is walked in order
		}
		previous := a.currentConfHash()
		a.confMu.Lock()
		a.confs = append(a.confs, confEntry{epoch: epoch, hash: bytes.Clone(h)})
		a.shardConfHash = bytes.Clone(h)
		a.confMu.Unlock()
		f.current = pdr
		if f.onAdopt != nil {
			f.onAdopt(previous, h)
		}
		return nil
	}
	return fmt.Errorf("%w: the certificate commits to configuration %X, which is none of the next %d epochs of the shard", ErrShardConfUnknown, sealed, maxConfLookahead)
}
