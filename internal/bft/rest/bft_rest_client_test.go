package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	type request struct {
		Partition uint32 `json:"partition"`
		Shard     string `json:"shard"`
		Epoch     uint64 `json:"epoch"`
	}
	var asked []request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/q3/shard-conf", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.Empty(t, r.Header.Get("Origin"))
		var q request
		require.NoError(t, json.NewDecoder(r.Body).Decode(&q))
		asked = append(asked, q)
		var shard types.ShardID
		if q.Shard != "" {
			require.NoError(t, shard.UnmarshalText([]byte(q.Shard)))
		}
		if !shard.Equal(left) && shard.Length() != 0 {
			http.Error(w, "no configuration", http.StatusUnprocessableEntity)
			return
		}
		require.NoError(t, json.NewEncoder(w).Encode(&types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: types.PartitionID(q.Partition), ShardID: shard, Epoch: q.Epoch}))
	}))
	defer srv.Close()
	c := NewBFTRestClient(srv.URL)
	pdr, err := c.ShardConfig(context.Background(), 7, left, 3)
	require.NoError(t, err)
	require.EqualValues(t, 3, pdr.Epoch)
	require.EqualValues(t, 7, pdr.PartitionID)
	require.True(t, pdr.ShardID.Equal(left))
	require.Equal(t, request{7, string(leftText), 3}, asked[0], "the shard id is passed through")

	pdr, err = c.ShardConfig(context.Background(), 7, types.ShardID{}, 1)
	require.NoError(t, err)
	require.Zero(t, pdr.ShardID.Length())
	require.Empty(t, asked[1].Shard, "the unsplit shard sends none")

	pdr, err = c.ShardConfig(context.Background(), 7, right, 1)
	require.NoError(t, err)
	require.Nil(t, pdr, "a configuration the root does not hold is none, not an error")

	absent := httptest.NewServer(http.NotFoundHandler()) // a root without the route at all
	defer absent.Close()
	_, err = NewBFTRestClient(absent.URL).ShardConfig(context.Background(), 7, left, 1)
	require.Error(t, err, "a 404 means the route is absent: it is never read as a missing epoch")

	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not an operator source", http.StatusForbidden)
	}))
	defer refuse.Close()
	_, err = NewBFTRestClient(refuse.URL).ShardConfig(context.Background(), 7, left, 1)
	require.Error(t, err, "a refused source is an error, not an absent configuration")
}
