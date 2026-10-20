// Package utbtest builds signed trust-base entries and certificates for tests.
package utbtest

import (
	"context"
	gocrypto "crypto"
	"crypto/sha256"
	"testing"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Fetcher answers GetTrustBase pages with a server in process (the libp2p stream is bft-core's).
type Fetcher struct{ Srv *gettrustbase.Server }

func (f *Fetcher) Page(_ context.Context, _ peer.ID, req *gettrustbase.Request) (*gettrustbase.Response, [][]byte, error) {
	resp := f.Srv.Respond(req)
	out := make([][]byte, len(resp.Entries))
	for i, e := range resp.Entries {
		out[i] = e
	}
	return resp, out, nil
}

// Member is a root committee member with a libp2p peer identity.
type Member struct {
	ID     string
	Signer crypto.Signer
}

// NewMembers creates n members with fresh keys.
func NewMembers(t *testing.T, n int) []Member {
	t.Helper()
	out := make([]Member, n)
	for i := range out {
		s, err := crypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		pub, err := p2pcrypto.UnmarshalSecp256k1PublicKey(key)
		require.NoError(t, err)
		id, err := peer.IDFromPublicKey(pub)
		require.NoError(t, err)
		out[i] = Member{ID: id.String(), Signer: s}
	}
	return out
}

// Entry builds a version 2 entry of unit weights: the genesis when prev is nil, otherwise the successor of prev signed by signers.
func Entry(t *testing.T, network types.NetworkID, epoch, start uint64, ms []Member, prev *types.RootTrustBaseV2, signers []Member) *types.RootTrustBaseV2 {
	t.Helper()
	e := types.NewRootTrustBaseV2()
	e.NetworkID, e.Epoch, e.EpochStart = network, epoch, start
	for _, m := range ms {
		v, err := m.Signer.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		e.RootNodes = append(e.RootNodes, &types.NodeInfo{NodeID: m.ID, SigKey: key, Stake: 1})
	}
	sortNodes(e.RootNodes)
	e.QuorumThreshold = uint64(len(ms))*2/3 + 1
	if prev == nil {
		e.PreviousEntryID = make([]byte, types.TrustBaseV2IDLen)
		return e
	}
	id, err := prev.EntryID()
	require.NoError(t, err)
	e.PreviousEntryID = id[:]
	for _, m := range signers {
		require.NoError(t, e.Sign(m.ID, m.Signer))
	}
	require.NoError(t, e.VerifySuccessor(prev))
	return e
}

func sortNodes(n []*types.NodeInfo) {
	for i := 1; i < len(n); i++ {
		for j := i; j > 0 && n[j-1].NodeID > n[j].NodeID; j-- {
			n[j-1], n[j] = n[j], n[j-1]
		}
	}
}

// Partition is the partition of the certificates Certificate builds.
const Partition types.PartitionID = 7

// Certificate builds a UC for one partition whose seal (epoch, root round, network) is signed by the given members.
func Certificate(t *testing.T, network types.NetworkID, epoch, rootRound uint64, signers []Member) *types.UnicityCertificate {
	t.Helper()
	trHash := sha256.Sum256([]byte("technical record"))
	return CertificateWithTR(t, network, epoch, rootRound, signers, trHash[:])
}

// CertificateWithTR is Certificate committing to the given technical record hash.
func CertificateWithTR(t *testing.T, network types.NetworkID, epoch, rootRound uint64, signers []Member, trHash []byte) *types.UnicityCertificate {
	t.Helper()
	ir := &types.InputRecord{Version: 1, RoundNumber: 3, Epoch: 0, PreviousHash: []byte{1}, Hash: []byte{2}, SummaryValue: []byte{3}, Timestamp: 1,
		BlockHash: []byte{4}, SumOfEarnedFees: 0, ETHash: []byte{5}}
	confHash := sha256.Sum256([]byte("shard conf"))
	sTree, err := types.CreateShardTree(types.ShardingScheme{}, []types.ShardTreeInput{{Shard: types.ShardID{}, IR: ir, TRHash: trHash,
		ShardConfHash: confHash[:]}}, gocrypto.SHA256)
	require.NoError(t, err)
	stCert, err := sTree.Certificate(types.ShardID{})
	require.NoError(t, err)
	ut, err := types.NewUnicityTree(gocrypto.SHA256, []*types.UnicityTreeData{{Partition: Partition, ShardTreeRoot: sTree.RootHash()}})
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: network, RootChainRoundNumber: rootRound, Epoch: epoch, Timestamp: 1_700_000_000,
		PreviousHash: []byte{9}, Hash: ut.RootHash()}
	for _, m := range signers {
		require.NoError(t, seal.Sign(m.ID, m.Signer))
	}
	utCert, err := ut.Certificate(Partition)
	require.NoError(t, err)
	return &types.UnicityCertificate{Version: 1, InputRecord: ir, TRHash: trHash, ShardConfHash: confHash[:], ShardTreeCertificate: stCert,
		UnicityTreeCertificate: utCert, UnicitySeal: seal}
}
