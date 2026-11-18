package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestBFTRestClient_GetTrustBases(t *testing.T) {
	tb := &types.RootTrustBaseV1{
		Epoch: 1,
	}

	tests := []struct {
		name     string
		epoch1   uint64
		epoch2   uint64
		handler  http.HandlerFunc
		wantErr  bool
		validate func(t *testing.T, result []*types.RootTrustBaseV1)
	}{
		{
			name:   "OK",
			epoch1: 1,
			epoch2: 1,
			handler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/api/v1/trustbases", r.URL.Path)
				require.Equal(t, "1", r.URL.Query().Get("from"))
				require.Equal(t, "1", r.URL.Query().Get("to"))
				require.Equal(t, "application/cbor", r.Header.Get("Accept"))

				w.Header().Set("Content-Type", "application/cbor")

				resp := GetTrustBasesResponse{
					TrustBases: []*types.RootTrustBaseV1{tb},
				}
				encoder, err := types.Cbor.GetEncoder(w)
				require.NoError(t, err)
				require.NoError(t, encoder.Encode(&resp))
			},
			validate: func(t *testing.T, result []*types.RootTrustBaseV1) {
				require.Len(t, result, 1)
				require.EqualValues(t, 1, result[0].Epoch)
			},
		},
		{
			name:   "HTTPError",
			epoch1: 2,
			epoch2: 1,
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "bad request", http.StatusBadRequest)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			client := NewBFTRestClient(srv.URL)
			result, err := client.GetTrustBases(context.Background(), tt.epoch1, tt.epoch2)

			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, result)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

func TestShardConfigAsksForTheShardAndEpochAndDecodesTheAnswer(t *testing.T) {
	left, right := types.ShardID{}.Split()
	leftText, _ := left.MarshalText()
	var query []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/shardConf", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		q := r.URL.Query()
		query = append(query, q)
		var shard types.ShardID
		if s := q.Get("shard"); s != "" {
			require.NoError(t, shard.UnmarshalText([]byte(s)))
		}
		if !shard.Equal(left) && shard.Length() != 0 {
			http.NotFound(w, r)
			return
		}
		epoch, _ := strconv.ParseUint(q.Get("epoch"), 10, 64)
		part, _ := strconv.ParseUint(q.Get("partition"), 10, 32)
		require.NoError(t, json.NewEncoder(w).Encode(&types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: types.PartitionID(part), ShardID: shard, Epoch: epoch}))
	}))
	defer srv.Close()
	c := NewBFTRestClient(srv.URL)
	pdr, err := c.ShardConfig(context.Background(), 7, left, 3)
	require.NoError(t, err)
	require.EqualValues(t, 3, pdr.Epoch)
	require.EqualValues(t, 7, pdr.PartitionID)
	require.True(t, pdr.ShardID.Equal(left))
	require.Equal(t, string(leftText), query[0].Get("shard"), "the shard id is passed through")

	pdr, err = c.ShardConfig(context.Background(), 7, types.ShardID{}, 1)
	require.NoError(t, err)
	require.Zero(t, pdr.ShardID.Length())
	require.False(t, query[1].Has("shard"), "the unsplit shard sends none")

	pdr, err = c.ShardConfig(context.Background(), 7, right, 1)
	require.NoError(t, err)
	require.Nil(t, pdr, "a configuration the root does not hold is none, not an error")
}
