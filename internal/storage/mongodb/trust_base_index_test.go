package mongodb

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

// Every index of the trust base collection is on a field the documents have. The start-round index
// used to be on "epochStart", a name no stored document carries (the field is "epochStartRound"),
// so it indexed nothing and the lookup by round scanned the collection.
func TestTrustBaseIndexesAreOnStoredFields(t *testing.T) {
	stored := map[string]bool{}
	typ := reflect.TypeOf(TrustBaseBSON{})
	for i := 0; i < typ.NumField(); i++ {
		if name, _, _ := strings.Cut(typ.Field(i).Tag.Get("bson"), ","); name != "" {
			stored[name] = true
		}
	}
	require.True(t, stored["epochStartRound"])

	var keys []string
	for _, model := range trustBaseIndexModels() {
		for _, e := range model.Keys.(bson.D) {
			require.True(t, stored[e.Key], "index key %q is not a stored field", e.Key)
			keys = append(keys, e.Key)
		}
	}
	// the by-round lookup (GetByRound) filters and sorts on this field
	require.Contains(t, keys, "epochStartRound")
	require.Contains(t, keys, "epoch")
}
