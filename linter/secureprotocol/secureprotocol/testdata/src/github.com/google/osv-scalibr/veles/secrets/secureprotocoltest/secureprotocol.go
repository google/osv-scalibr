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
	Endpoint: insecureBase + "/account", // want `hardcoded validator endpoint "http://api.example.com/account" uses insecure protocol "http"; use HTTPS`
}

var _ = &simplevalidate.Validator[string]{
	Endpoints: []string{
		"https://api.example.com/one",
		"ftp://api.example.com/two", // want `hardcoded validator endpoint "ftp://api.example.com/two" uses insecure protocol "ftp"; use HTTPS`
	},
}

func requests(ctx context.Context, dynamicURL string) {
	_, _ = http.NewRequest(http.MethodGet, "http://api.example.com/account", nil) // want `hardcoded validator endpoint "http://api.example.com/account" uses insecure protocol "http"; use HTTPS`
	_, _ = http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/account", nil)
	_, _ = http.NewRequest(http.MethodGet, dynamicURL, nil)
}
