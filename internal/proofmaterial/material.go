// Package proofmaterial carries the optional partition view ("sidecar") received
// with a CertificationResponseV2 from transport intake to whoever publishes proof
// views. It never influences ordinary UC processing.
package proofmaterial

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

// Digest identifies a complete unicity certificate (SHA-256 of its CBOR encoding).
type Digest [sha256.Size]byte

// DigestOfUC returns the digest and canonical encoding of the UC.
func DigestOfUC(uc *types.UnicityCertificate) (Digest, []byte, error) {
	if uc == nil {
		return Digest{}, nil, errors.New("nil unicity certificate")
	}
	b, err := types.Cbor.Marshal(uc)
	if err != nil {
		return Digest{}, nil, fmt.Errorf("encoding unicity certificate: %w", err)
	}
	return sha256.Sum256(b), b, nil
}

// IsUnshardedUC reports whether the UC is structurally that of an unsharded partition: empty shard
// ID and zero shard-tree siblings (its shard tree is a single leaf). Such a UC already commits to
// everything a one-leaf partition view would repeat, so no sidecar is needed, staged or served for it.
// Components are checked before they are dereferenced.
func IsUnshardedUC(uc *types.UnicityCertificate) bool {
	if uc == nil || uc.InputRecord == nil || uc.UnicitySeal == nil || uc.UnicityTreeCertificate == nil {
		return false
	}
	return uc.ShardTreeCertificate.Shard.Length() == 0 && len(uc.ShardTreeCertificate.SiblingHashes) == 0
}

// Kind tells why material is published.
type Kind int

const (
	// KindFinalized: UC accepted and the local state it certifies is finalized.
	KindFinalized Kind = iota
	// KindRepeat: operationally accepted repeat/timeout UC; no new local state was
	// finalized. Consumers must only attach it to a matching finalized state/IR lineage.
	KindRepeat
	// KindSidecarFill: a duplicate delivery of an already published UC added a
	// previously missing valid partition view.
	KindSidecarFill
	// KindInitial: the UC the client was initialized with (startup or first UC). It
	// certifies the state the node already holds; the only state it can publish is the
	// certified EMPTY tree of a node without any committed block. Consumers ignore it
	// for any other root (published by the normal startup/finalization paths).
	KindInitial
)

func (k Kind) String() string {
	switch k {
	case KindFinalized:
		return "finalized"
	case KindRepeat:
		return "repeat"
	case KindSidecarFill:
		return "sidecar_fill"
	case KindInitial:
		return "initial"
	}
	return "unknown"
}

// Material is an immutable publication. Consumers must not modify the slices.
type Material struct {
	Kind Kind
	// UC is the accepted certificate, UCBytes its canonical encoding, UCDigest its digest.
	UC       *types.UnicityCertificate
	UCBytes  []byte
	UCDigest Digest
	// PartitionView is the validated canonical PartitionViewV1 CBOR bound to exactly
	// this UC, or nil when no valid sidecar was received for it.
	PartitionView []byte
	// BlockNumber is the local finalized block identity for KindFinalized, otherwise
	// nil/unset (HasBlock false). It is never derived from the technical record.
	BlockNumber uint64
	HasBlock    bool
}

// Sink consumes published proof material. A4 wires it to the retained-view catalog.
// Implementations must not block certification; errors are logged and counted by the
// caller and never fail finalization.
type Sink interface {
	PublishProofMaterial(ctx context.Context, m *Material) error
}

// NopSink discards material.
type NopSink struct{}

func (NopSink) PublishProofMaterial(context.Context, *Material) error { return nil }

// TopologyProvider optionally returns an independently pinned topology of the partition:
// its complete sharding scheme and the admitted configuration hash (exactly 32 bytes) of
// every shard. It must come from the deployment's own configuration, never from a
// response. Pins only restrict: without them the topology is the one committed by the
// authenticated seal. A partition it cannot resolve yields (_, false): no pins.
type TopologyProvider interface {
	Topology(partition types.PartitionID) (types.PartitionViewTopology, bool)
}

// Validation outcomes used as metric labels.
const (
	ResultOK        = "ok"
	ResultMissing   = "missing"
	ResultMalformed = "malformed"
	ResultInvalid   = "invalid"
	ResultTooLarge  = "too_large"
	// ResultNoTopology: the configured pinned topology is itself unusable.
	ResultNoTopology = "no_trusted_topology"
)

// ConfHashSize is the required size of every admitted shard configuration hash.
const ConfHashSize = 32

// ValidateView authenticates the partition view of a response end to end
// (types.AuthenticatePartitionView): the view is decoded as untrusted data, must
// hash into the seal of the enclosing UC under the caller's expected partition,
// match the enclosing UC's own leaf exactly, and the complete seal must be
// authenticated by "verifier" (network, exact epoch, epoch start, quorum). The
// scheme and configuration hashes are then those committed by the seal.
//
// "pins" is an OPTIONAL independently admitted topology: when it resolves the
// partition the view must also match it (stricter). Returns the outcome label and, on
// success, a private copy of the bytes. Any failure only means "no proof material".
func ValidateView(raw []byte, uc *types.UnicityCertificate, verifier types.SealVerifier, pins TopologyProvider) (string, []byte, error) {
	if len(raw) == 0 {
		return ResultMissing, nil, nil
	}
	if len(raw) > types.MaxPartitionViewBytes {
		return ResultTooLarge, nil, fmt.Errorf("partition view is %d bytes, limit %d", len(raw), types.MaxPartitionViewBytes)
	}
	view, err := types.DecodePartitionViewV1(raw)
	if err != nil {
		return ResultMalformed, nil, err
	}
	var opts []types.AuthOption
	if st, ok := pins.(*StaticTopology); ok && st != nil {
		pins = viewPins{st.forView(view)} // following shards move with the configurations resolved; fixed pins do not
	}
	if topo, ok := topologyFor(pins, api.AggregationPartitionID); ok {
		if err := checkTopology(topo); err != nil {
			return ResultNoTopology, nil, err
		}
		opts = append(opts, types.WithPinnedTopology(topo))
	}
	if _, err := types.AuthenticateView(view, uc, api.AggregationPartitionID, verifier, crypto.SHA256, opts...); err != nil {
		return ResultInvalid, nil, err
	}
	return ResultOK, append([]byte(nil), raw...), nil
}

// checkTopology requires a valid complete scheme and a 32-byte hash for every shard.
func checkTopology(topo types.PartitionViewTopology) error {
	order, err := types.CanonicalShardOrder(topo.Scheme)
	if err != nil {
		return fmt.Errorf("trusted topology: %w", err)
	}
	for _, id := range order {
		if h := topo.ShardConfHashes[id.Key()]; len(h) != ConfHashSize {
			return fmt.Errorf("trusted topology: shard %q has no %d-byte configuration hash", id, ConfHashSize)
		}
	}
	return nil
}

// StaticTopology is a fixed trusted topology of the aggregation partition (api.AggregationPartitionID).
type StaticTopology struct {
	mu     sync.RWMutex
	topo   types.PartitionViewTopology
	follow map[string]bool
	known  func(shard types.ShardID, hash []byte) bool
}

// NewStaticTopology builds and checks a trusted topology: scheme must be complete and
// every shard needs a 32-byte configuration hash (keyed by ShardID.Key()).
func NewStaticTopology(scheme types.ShardingScheme, confHashes map[string][]byte) (*StaticTopology, error) {
	topo := types.PartitionViewTopology{Scheme: scheme, ShardConfHashes: map[string][]byte{}}
	for k, v := range confHashes {
		topo.ShardConfHashes[k] = append([]byte(nil), v...)
	}
	if err := checkTopology(topo); err != nil {
		return nil, err
	}
	return &StaticTopology{topo: topo}, nil
}

// SingleShardTopology is the trusted topology of an unsharded partition: the empty
// scheme with the deployment's own shard configuration hash.
func SingleShardTopology(shardConfHash []byte) (*StaticTopology, error) {
	return NewStaticTopology(types.ShardingScheme{}, map[string][]byte{types.ShardID{}.Key(): shardConfHash})
}

func (s *StaticTopology) Topology(partition types.PartitionID) (types.PartitionViewTopology, bool) {
	if s == nil || partition != api.AggregationPartitionID {
		return types.PartitionViewTopology{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.topo, true
}

// Pin is the configuration hash pinned for a shard.
func (s *StaticTopology) Pin(shard types.ShardID) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.topo.ShardConfHashes[shard.Key()]
	return h, ok
}

// SetFollowing marks the shards (by ShardID.Key()) whose pins follow live configuration changes; every other pin is fixed.
func (s *StaticTopology) SetFollowing(shards map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.follow = make(map[string]bool, len(shards))
	for k, v := range shards {
		s.follow[k] = v
	}
}

// Following reports whether the pin of the shard follows live configuration changes.
func (s *StaticTopology) Following(shard types.ShardID) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.follow[shard.Key()]
}

// SetKnown connects the topology to the configurations a client resolved: known reports whether a hash is a verified configuration of a shard.
func (s *StaticTopology) SetKnown(known func(shard types.ShardID, hash []byte) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.known = known
}

// forView is the topology a view is validated against: the pins, where a following shard's pin is replaced by the hash its leaf commits to
// when that is a verified configuration of that shard. A fixed pin is never replaced, and the receiver is not modified. This one rule serves
// live intake and the revalidation of stored views alike.
func (s *StaticTopology) forView(view *types.PartitionViewV1) types.PartitionViewTopology {
	s.mu.RLock()
	defer s.mu.RUnlock()
	topo := s.topo
	if s.known == nil || len(s.follow) == 0 {
		return topo
	}
	var next map[string][]byte
	for _, leaf := range view.Leaves {
		k := leaf.ShardID.Key()
		pin, ok := topo.ShardConfHashes[k]
		if !ok || !s.follow[k] || bytes.Equal(pin, leaf.ShardConfHash) || len(leaf.ShardConfHash) != ConfHashSize || !s.known(leaf.ShardID, leaf.ShardConfHash) {
			continue
		}
		if next == nil {
			next = make(map[string][]byte, len(topo.ShardConfHashes))
			for kk, v := range topo.ShardConfHashes {
				next[kk] = v
			}
		}
		next[k] = leaf.ShardConfHash
	}
	if next == nil {
		return topo
	}
	return types.PartitionViewTopology{Scheme: topo.Scheme, ShardConfHashes: next}
}

// viewPins is the pinned topology of one validation.
type viewPins struct{ topo types.PartitionViewTopology }

func (v viewPins) Topology(partition types.PartitionID) (types.PartitionViewTopology, bool) {
	if partition != api.AggregationPartitionID {
		return types.PartitionViewTopology{}, false
	}
	return v.topo, true
}

func topologyFor(p TopologyProvider, partition types.PartitionID) (types.PartitionViewTopology, bool) {
	if p == nil {
		return types.PartitionViewTopology{}, false
	}
	return p.Topology(partition)
}
