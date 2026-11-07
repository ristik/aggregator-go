package gateway

import (
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/logger"
	"github.com/unicitynetwork/aggregator-go/internal/utb"
	"github.com/unicitynetwork/aggregator-go/internal/utb/utbtest"
)

// The owner's §49 profile at its ceiling, end to end through the aggregator's own history: a 256-member genesis, a 256-member successor sealed by all
// 256 predecessor members is appended, persisted, reloaded from the store after a restart and served over HTTP; a 257-member successor is refused.
func TestMaximumCommitteeAppendPersistRestartServe(t *testing.T) {
	const n = 256
	net := types.NetworkID(3)
	ms := utbtest.NewMembers(t, n)
	g := utbtest.Entry(t, net, 1, 1, ms, nil, nil)
	e2 := utbtest.Entry(t, net, 2, 10, ms, g, ms)
	gRaw, err := g.MarshalCBOR()
	require.NoError(t, err)
	e2Raw, err := e2.MarshalCBOR()
	require.NoError(t, err)
	require.Less(t, len(e2Raw), 128<<10, "a 256-member entry with 256 predecessor signatures fits the per-entry cap")
	t.Logf("256-member entry with 256 signatures: %d bytes", len(e2Raw))
	gid, err := g.EntryID()
	require.NoError(t, err)

	dir := t.TempDir()
	genesis := filepath.Join(dir, "genesis.cbor")
	require.NoError(t, os.WriteFile(genesis, gRaw, 0o600))
	db := filepath.Join(dir, "utb.db")
	pin := "0x" + hex.EncodeToString(gid[:])

	h, err := utb.Open("", genesis, pin, db)
	require.NoError(t, err)
	added, gap, err := h.Ingest([][]byte{e2Raw})
	require.NoError(t, err)
	require.False(t, gap)
	require.Equal(t, 1, added)
	require.Equal(t, uint64(2), h.Tip().Epoch)
	require.NoError(t, h.Close())

	// Restart from the genesis alone: the second entry comes back from the durable store.
	h, err = utb.Open("", genesis, pin, db)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	require.Equal(t, uint64(2), h.Tip().Epoch)

	srv, err := gettrustbase.NewServer(h.Source(), gettrustbase.Config{})
	require.NoError(t, err)
	log, err := logger.New("warn", "text", "stdout", false)
	require.NoError(t, err)
	hf := getTrustBaseHistoryHandler(log, srv, h.Network(), h.GenesisEpoch())
	res, body := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases")
	require.Equal(t, http.StatusOK, res.StatusCode)
	resp, _, err := gettrustbase.DecodeResponse(body, gettrustbase.PageLimits)
	require.NoError(t, err)
	require.Equal(t, gettrustbase.StatusOK, resp.Status)
	require.Len(t, resp.Entries, 2)
	// The served bytes are the stored signed entry: the same entry id and all 256 predecessor signatures (the signature map's encoding order is not
	// part of the id).
	var served types.RootTrustBaseV2
	require.NoError(t, served.UnmarshalCBOR(resp.Entries[1]))
	sid, err := served.EntryID()
	require.NoError(t, err)
	id2, err := e2.EntryID()
	require.NoError(t, err)
	require.Equal(t, id2, sid)
	require.Len(t, served.Signatures, n)
	require.NoError(t, served.VerifySuccessor(g))

	// One member over the ceiling is refused, and the held history does not change.
	over := types.NewRootTrustBaseV2()
	over.NetworkID, over.Epoch, over.EpochStart = net, 3, 20
	for _, m := range utbtest.NewMembers(t, n+1) {
		v, err := m.Signer.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		over.RootNodes = append(over.RootNodes, &types.NodeInfo{NodeID: m.ID, SigKey: key, Stake: 1})
	}
	over.QuorumThreshold = n + 1
	id2b := id2
	over.PreviousEntryID = id2b[:]
	for _, m := range ms {
		require.NoError(t, over.Sign(m.ID, m.Signer))
	}
	bad, err := over.MarshalCBOR()
	require.NoError(t, err)
	e3Raw := bad
	_, _, err = h.Ingest([][]byte{e3Raw})
	require.ErrorContains(t, err, "257 members")
	require.Equal(t, uint64(2), h.Tip().Epoch)
}
