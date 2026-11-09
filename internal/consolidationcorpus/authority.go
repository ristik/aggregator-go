package consolidationcorpus

import (
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// An authority in a corpus is a Unicity Trust Base v2 bundle (tag 39015, the GET /api/v1/trustbases form) holding the single genesis
// entry of the authority; a verifier opens it as a trust base history pinned to that genesis. No version-1 trust base and no JSON form
// is part of a corpus.

// AuthorityBundle is the bundle of the genesis entry with the network, epoch, start round, members (stake is the voting weight) and
// quorum of the producer's trust base t. The entry rules apply: the quorum must be floor(2W/3)+1 of the total weight.
func AuthorityBundle(t *types.RootTrustBaseV1) ([]byte, error) {
	e := types.NewRootTrustBaseV2()
	e.NetworkID, e.Epoch, e.EpochStart = t.NetworkID, t.Epoch, t.EpochStart
	e.RootNodes = t.RootNodes
	e.QuorumThreshold = t.QuorumThreshold
	e.StateHash, e.ChangeRecordHash = t.StateHash, t.ChangeRecordHash
	e.PreviousEntryID = make([]byte, types.TrustBaseV2IDLen)
	return EntryBundle(e)
}

// EntryBundle encodes one genesis entry as a bundle.
func EntryBundle(e *types.RootTrustBaseV2) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, fmt.Errorf("the authority is not a valid trust base v2 genesis entry: %w", err)
	}
	raw, err := e.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	return types.EncodeTrustBaseBundle([][]byte{raw})
}

// DecodeAuthority opens an authority bundle: exactly one genesis entry, pinned by its own EntryID.
func DecodeAuthority(b []byte) (*types.RootTrustBaseV2, error) {
	bundle, err := types.DecodeTrustBaseBundle(b, types.TrustBaseLimits{MaxBytes: len(b), MaxEntries: 1})
	if err != nil {
		return nil, err
	}
	if len(bundle.Entries) != 1 {
		return nil, fmt.Errorf("an authority bundle holds exactly one entry, not %d", len(bundle.Entries))
	}
	e := bundle.Entries[0]
	id, err := e.EntryID()
	if err != nil {
		return nil, err
	}
	if err := types.VerifyTrustBaseBundle(bundle, id); err != nil {
		return nil, err
	}
	if err := e.VerifyGenesis(); err != nil {
		return nil, err
	}
	return e, nil
}
