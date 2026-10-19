package bft

import (
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/utb/utbtest"
)

// The shard's certificates must commit to the shard's own configuration: the client pins the hash of
// the configured shard configuration (it used to pass nil, accepting a certificate of any configuration).
func TestTheClientPinsTheHashOfItsShardConfiguration(t *testing.T) {
	c, _, _, _, _, _ := threeEpochs(t, utbtest.Partition)
	want, err := c.conf.ShardConf.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, want, c.authn.shardConfHash)
	require.NotEmpty(t, c.authn.shardConfHash)
}

func TestACertificateOfAnotherShardConfigurationIsRefused(t *testing.T) {
	c, _, _, j, _, _ := threeEpochs(t, utbtest.Partition)
	uc := utbtest.Certificate(t, 5, 2, 150, j[:3])
	verify := func() error {
		return c.authn.beginIntake(context.Background()).verifyUC(uc, utbtest.Partition, types.ShardID{})
	}

	// the certificate's own configuration is accepted as far as configuration goes (the epoch is
	// not admitted yet, which is a different, retryable outcome)
	c.authn.withShardConfHash(uc.ShardConfHash)
	require.ErrorIs(t, verify(), ErrEpochNotAdmitted)

	// any other configuration hash: refused before any authority is consulted
	other := append([]byte(nil), uc.ShardConfHash...)
	other[0] ^= 1
	c.authn.withShardConfHash(other)
	err := verify()
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrEpochNotAdmitted)
	require.Contains(t, err.Error(), "invalid shard configuration hash")
}
