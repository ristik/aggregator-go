package bft

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/config"
	"github.com/unicitynetwork/aggregator-go/internal/logger"
	"github.com/unicitynetwork/aggregator-go/internal/metrics"
	"github.com/unicitynetwork/aggregator-go/internal/models"
	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

// A lagging root answers a handshake with a certificate older than the held one (the milestone lane: partition round 216 at root round 840 after 843). It is refused
// as before, but it is routine: nothing is logged at ERROR, the held UC and the pending request are untouched and it is counted. Real sequence faults stay ERROR.
func TestBFTClientStaleUCIsIgnoredNotAFault(t *testing.T) {
	root := bytes.Repeat([]byte{0x10}, api.SiblingSize)
	t0 := time.Unix(1_700_000_000, 0)

	type fixture struct {
		c         *BFTClientImpl
		out       *bytes.Buffer
		delivered int
		held      *types.UnicityCertificate
		pending   *pendingRequest
	}
	setup := func() *fixture {
		f := &fixture{out: &bytes.Buffer{}}
		f.c = &BFTClientImpl{
			logger:       &logger.Logger{Logger: slog.New(slog.NewJSONHandler(f.out, &slog.HandlerOptions{Level: slog.LevelDebug}))},
			roundManager: &stubRoundManager{committedRoot: root},
			conf:         &config.BFTConfig{},
		}
		f.c.status.Store(normal)
		f.c.now = func() time.Time { return t0 }
		f.c.deliver = func(context.Context, *certification.BlockCertificationRequest, *types.UnicityCertificate) error {
			f.delivered++
			return nil
		}
		f.held = testUnicityCertificate(11, 21, root, nil)
		f.c.luc.Store(f.held)
		f.c.lastRootRound.Store(21)
		f.c.nextExpectedRound.Store(12)
		f.c.lastCertResponseTime.Store(t0.UnixMilli())
		f.c.proposedBlock = models.NewBlock(api.NewBigIntFromUint64(12), "unicity", 0, "1.0", "mainnet", api.NewHexBytes(bytes.Repeat([]byte{0x20}, api.SiblingSize)), api.NewHexBytes(root), nil, testSealTimestamp)
		f.pending = &pendingRequest{round: 12, req: &certification.BlockCertificationRequest{PartitionID: f.c.PartitionID(), InputRecord: &types.InputRecord{Version: 1, RoundNumber: 12}, Signature: []byte("signed-once")}, sentAt: t0.Add(-time.Hour)}
		f.c.pending = f.pending
		return f
	}
	answer := func(f *fixture, uc *types.UnicityCertificate) error {
		err := f.c.handleUnicityCertificate(t.Context(), uc, &certification.TechnicalRecord{Round: 12, Epoch: 1})
		if err != nil {
			f.c.logResponseError(t.Context(), "CertificationResponseV3", err)
		}
		return err
	}
	untouched := func(t *testing.T, f *fixture) {
		require.Same(t, f.held, f.c.luc.Load(), "the held UC")
		require.EqualValues(t, 21, f.c.lastRootRound.Load())
		require.EqualValues(t, 12, f.c.nextExpectedRound.Load())
		require.Same(t, f.pending, f.c.pending, "the pending request")
		require.Zero(t, f.delivered, "and it was not re-sent")
		require.EqualValues(t, t0.UnixMilli(), f.c.lastCertResponseTime.Load(), "a stale answer is not liveness")
	}
	count := func() float64 {
		return testutil.ToFloat64(metrics.BFTStaleUCTotal.WithLabelValues(types.ShardID{}.String()))
	}

	for name, stale := range map[string]*types.UnicityCertificate{
		"the held partition round re-issued at an earlier root round": testUnicityCertificate(11, 20, root, nil),
		"an older partition round at an older root round":             testUnicityCertificate(10, 19, bytes.Repeat([]byte{0x09}, api.SiblingSize), nil),
	} {
		t.Run(name, func(t *testing.T) {
			f := setup()
			before := count()
			err := answer(f, stale)
			require.ErrorIs(t, err, ErrStaleUC)
			require.ErrorIs(t, err, ErrInvalidUCSequence, "the refusal is unchanged")
			require.NotContains(t, f.out.String(), `"level":"ERROR"`)
			require.Contains(t, f.out.String(), `"level":"DEBUG"`)
			require.Contains(t, f.out.String(), "stale unicity certificate")
			require.Equal(t, before+1, count())
			untouched(t, f)
		})
	}

	t.Run("real sequence faults are still errors", func(t *testing.T) {
		f := setup()
		before := count()
		// an older partition round certified at a LATER root round than the held one: no honest root chain issues it
		err := answer(f, testUnicityCertificate(10, 25, bytes.Repeat([]byte{0x09}, api.SiblingSize), nil))
		require.ErrorIs(t, err, ErrInvalidUCSequence)
		require.NotErrorIs(t, err, ErrStaleUC)
		require.Equal(t, 1, strings.Count(f.out.String(), `"level":"ERROR"`))
		require.Equal(t, before, count())
		// the same partition round with another input record: equivocation, whether it arrives with a later or an EARLIER root round (an older root round alone is not stale)
		for _, rootRound := range []uint64{22, 20} {
			f = setup()
			err = answer(f, testUnicityCertificate(11, rootRound, bytes.Repeat([]byte{0x11}, api.SiblingSize), nil))
			require.ErrorIs(t, err, ErrInvalidUCSequence)
			require.NotErrorIs(t, err, ErrStaleUC, "root round %d", rootRound)
			require.Contains(t, f.out.String(), `"level":"ERROR"`, "root round %d", rootRound)
		}
	})
}
