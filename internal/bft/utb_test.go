package bft

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/config"
	"github.com/unicitynetwork/aggregator-go/internal/logger"
	"github.com/unicitynetwork/aggregator-go/internal/utb"
	"github.com/unicitynetwork/aggregator-go/internal/utb/utbtest"
)

type utbVectors struct {
	GenesisEntry   string   `json:"genesisEntry"`
	GenesisEntryID string   `json:"genesisEntryId"`
	Entries        []string `json:"entries"`
	AcceptedTwo    string   `json:"acceptedTwo"`
	RejectedOne    string   `json:"rejectedOne"`
}

// utbClient is a BFT client whose trust-base provider is a signed history holding the fixture genesis.
func utbClient(t *testing.T) (*BFTClientImpl, *utb.History, *utbVectors) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "utb", "testdata", "ucresp_v2_vectors.json"))
	require.NoError(t, err)
	var v utbVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	g, err := hex.DecodeString(v.GenesisEntry)
	require.NoError(t, err)
	dir := t.TempDir()
	genesis := filepath.Join(dir, "genesis.cbor")
	require.NoError(t, os.WriteFile(genesis, g, 0o600))
	h, err := utb.Open("", genesis, "0x"+v.GenesisEntryID, filepath.Join(dir, "utb.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	log, err := logger.New("warn", "text", "stdout", false)
	require.NoError(t, err)
	cr := decodeVector(t, v.AcceptedTwo)
	c, err := NewBFTClient(context.Background(), &config.BFTConfig{ShardConf: &types.PartitionDescriptionRecord{PartitionID: cr.Partition, ShardID: cr.Shard}},
		nil, h, nil, log, nil)
	require.NoError(t, err)
	require.Same(t, h, c.utb) // the client recognized the signed history
	return c, h, &v
}

func decodeVector(t *testing.T, s string) *certification.CertificationResponseV2 {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	var cr certification.CertificationResponseV2
	require.NoError(t, types.Cbor.Unmarshal(b, &cr))
	return &cr
}

// The attached entries are an authority update: they are appended before the certificate is looked at, whatever happens to the certificate, and a
// certificate whose authority is unknown advances nothing. The rejected response's entry (epoch 4) does not follow the held tip, so it is not appended
// (the client asks for the range; with no peer connected nothing more happens).
func TestCertificationResponseV2EntriesBeforeTheCertificate(t *testing.T) {
	c, h, v := utbClient(t)
	ctx := context.Background()

	// the fixture's certificate carries no seal: it never verifies, which isolates the entries' handling from the certificate's
	err := c.handleCertificationResponseV2(ctx, decodeVector(t, v.RejectedOne))
	require.ErrorIs(t, err, utb.ErrCertificate)
	require.Equal(t, uint64(1), h.Tip().Epoch)
	require.Nil(t, c.luc.Load())

	err = c.handleCertificationResponseV2(ctx, decodeVector(t, v.AcceptedTwo))
	require.ErrorIs(t, err, utb.ErrCertificate)
	require.Equal(t, uint64(3), h.Tip().Epoch) // appended before and independently of the certificate's verification
	require.Nil(t, c.luc.Load())               // a refused certificate advances nothing

	err = c.handleCertificationResponseV2(ctx, decodeVector(t, v.RejectedOne))
	require.ErrorIs(t, err, utb.ErrCertificate)
	require.Equal(t, uint64(4), h.Tip().Epoch) // a rejection's valid entry is kept
	require.Nil(t, c.luc.Load())
}

// Without a signed history the attached entries are ignored and the certificate is judged by the legacy path.
func TestCertificationResponseV2WithoutHistory(t *testing.T) {
	_, _, v := utbClient(t)
	log, err := logger.New("warn", "text", "stdout", false)
	require.NoError(t, err)
	cr := decodeVector(t, v.AcceptedTwo)
	c, err := NewBFTClient(context.Background(), &config.BFTConfig{ShardConf: &types.PartitionDescriptionRecord{PartitionID: cr.Partition, ShardID: cr.Shard}},
		nil, missingTrustBases{}, nil, log, nil)
	require.NoError(t, err)
	require.Nil(t, c.utb)
	require.ErrorContains(t, c.handleCertificationResponseV2(context.Background(), cr), "no trust base")
}

type missingTrustBases struct{}

func (missingTrustBases) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return nil, errNoTrustBase
}

var errNoTrustBase = errors.New("no trust base")

// twoEpochs is a client holding only the genesis of a two-epoch chain and an in-process root holding both entries.
func twoEpochs(t *testing.T, partition types.PartitionID) (*BFTClientImpl, *utb.History, *gettrustbase.Server, []utbtest.Member) {
	t.Helper()
	const net types.NetworkID = 5
	k, j := utbtest.NewMembers(t, 4), utbtest.NewMembers(t, 4)
	g := utbtest.Entry(t, net, 1, 1, k, nil, nil)
	e2 := utbtest.Entry(t, net, 2, 100, j, g, k[:3])
	graw, err := g.MarshalCBOR()
	require.NoError(t, err)
	e2raw, err := e2.MarshalCBOR()
	require.NoError(t, err)
	gid, err := g.EntryID()
	require.NoError(t, err)
	pin := "0x" + hex.EncodeToString(gid[:])
	dir := t.TempDir()
	genesis := filepath.Join(dir, "genesis.cbor")
	require.NoError(t, os.WriteFile(genesis, graw, 0o600))
	bundle, err := gettrustbase.EncodeBundle([][]byte{graw, e2raw})
	require.NoError(t, err)
	bundleFile := filepath.Join(dir, "root.cbor")
	require.NoError(t, os.WriteFile(bundleFile, bundle, 0o600))

	h, err := utb.Open("", genesis, pin, filepath.Join(dir, "client.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	root, err := utb.Open(bundleFile, "", pin, filepath.Join(dir, "root.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })
	srv, err := gettrustbase.NewServer(root.Source(), gettrustbase.Config{})
	require.NoError(t, err)

	log, err := logger.New("warn", "text", "stdout", false)
	require.NoError(t, err)
	c, err := NewBFTClient(context.Background(), &config.BFTConfig{ShardConf: &types.PartitionDescriptionRecord{PartitionID: partition}}, nil, h, nil, log, nil)
	require.NoError(t, err)
	return c, h, srv, j
}

// A certificate of an epoch the client does not hold starts one catch-up, and the certificate is verified again: that retry is what lets the new
// committee's first certificate through.
func TestVerifyUCCatchesUpAndRetries(t *testing.T) {
	c, h, srv, j := twoEpochs(t, utbtest.Partition)
	uc := utbtest.Certificate(t, 5, 2, 150, j[:3])

	require.ErrorIs(t, c.verifyUC(context.Background(), uc), utb.ErrUnknownEpoch) // no peer to ask: the authority stays unknown
	require.Equal(t, uint64(1), h.Tip().Epoch)

	c.trustBaseFetcher = &utbtest.Fetcher{Srv: srv}
	require.NoError(t, c.verifyUC(context.Background(), uc))
	require.Equal(t, uint64(2), h.Tip().Epoch)
}

// A response for another shard is refused before its certificate is looked at, so it never starts a catch-up.
func TestWrongShardNeverCatchesUp(t *testing.T) {
	c, h, srv, j := twoEpochs(t, utbtest.Partition+1)
	c.trustBaseFetcher = &utbtest.Fetcher{Srv: srv}
	tr := certification.TechnicalRecord{Round: 4, Epoch: 2, Leader: "leader", StatHash: []byte{1}, FeeHash: []byte{1}}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	uc := utbtest.CertificateWithTR(t, 5, 2, 150, j[:3], trHash)
	cr := &certification.CertificationResponse{Partition: utbtest.Partition, UC: *uc, Technical: tr}
	require.NoError(t, cr.IsValid())

	require.ErrorContains(t, c.handleCertificationResponse(context.Background(), cr), "wrong shard")
	require.Equal(t, uint64(1), h.Tip().Epoch)
}

// A restart with a fresh store: the last certificate's epoch is not held and cannot be fetched, so the handshake greets the newest held committee
// instead of failing (an initial handshake failure would end the client's message loop).
func TestHandshakeFallsBackToTheNewestHeldCommittee(t *testing.T) {
	c, h, _, j := twoEpochs(t, utbtest.Partition)
	c.luc.Store(utbtest.Certificate(t, 5, 2, 150, j[:3])) // epoch 2, not held, no peer to ask

	ids, err := c.handshakeTargets(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, ids)
	g, err := h.Committee(1)
	require.NoError(t, err)
	members := map[string]bool{}
	for _, n := range g.RootNodes {
		members[n.NodeID] = true
	}
	for _, id := range ids {
		require.True(t, members[id.String()], "handshake target %s is not a genesis committee member", id)
	}
}
