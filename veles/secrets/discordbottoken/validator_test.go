package discordbottoken_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/discordbottoken"
)

const validatorTestToken = "MTIzNDU2Nzg5MDEyMzQ1Njc4.YAaBbC.dEFGhijklMNOPqrSTUVwxyzAB"

func mockDiscordServer(t *testing.T, expectedToken string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v10/users/@me" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bot "+expectedToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
}

func TestValidator(t *testing.T) {
	server := mockDiscordServer(t, validatorTestToken)
	defer server.Close()

	client := &http.Client{
		Transport: discordbottoken.TestTransport(server.URL),
	}

	validator := discordbottoken.NewValidator(
		discordbottoken.WithClient(client),
	)

	cases := []struct {
		name  string
		token string
		want  veles.ValidationStatus
	}{
		{
			name:  "valid bot token",
			token: validatorTestToken,
			want:  veles.ValidationValid,
		},
		{
			name:  "invalid bot token",
			token: "invalid.token.value",
			want:  veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validator.Validate(
				context.Background(),
				discordbottoken.DiscordBotToken{},
				tc.token,
			)

			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}

			if !cmp.Equal(got, tc.want) {
				t.Fatalf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}
