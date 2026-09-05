package secureprotocoltest

import (
	"context"
	"net/http"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const insecureBase = "http://api.example.com"

var _ = &simplevalidate.Validator[string]{
	Endpoint: "https://api.example.com/account",
}

var _ = &simplevalidate.Validator[string]{
	Endpoint: insecureBase + "/account", // want `hardcoded HTTP validator endpoint "http://api.example.com/account" uses scheme "http"; use HTTPS`
}

var _ = &simplevalidate.Validator[string]{
	Endpoints: []string{
		"https://api.example.com/one",
		"http://api.example.com/two", // want `hardcoded HTTP validator endpoint "http://api.example.com/two" uses scheme "http"; use HTTPS`
	},
}

func requests(ctx context.Context, dynamicURL string) {
	_, _ = http.NewRequest(http.MethodGet, "http://api.example.com/account", nil) // want `hardcoded HTTP validator endpoint "http://api.example.com/account" uses scheme "http"; use HTTPS`
	_, _ = http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/account", nil)
	_, _ = http.NewRequest(http.MethodGet, dynamicURL, nil)
}
