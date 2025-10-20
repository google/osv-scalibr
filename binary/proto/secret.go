// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proto

import (
	"errors"
	"fmt"
	"time"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/mariadb"
	velesonepasswordconnecttoken "github.com/google/osv-scalibr/extractor/filesystem/secrets/onepasswordconnecttoken"
	velespgpass "github.com/google/osv-scalibr/extractor/filesystem/secrets/pgpass"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles"
	velesanthropicapikey "github.com/google/osv-scalibr/veles/secrets/anthropicapikey"
	velesazurestorageaccountaccesskey "github.com/google/osv-scalibr/veles/secrets/azurestorageaccountaccesskey"
	velesazuretoken "github.com/google/osv-scalibr/veles/secrets/azuretoken"
	"github.com/google/osv-scalibr/veles/secrets/cratesioapitoken"
	velesdigitalocean "github.com/google/osv-scalibr/veles/secrets/digitaloceanapikey"
	"github.com/google/osv-scalibr/veles/secrets/dockerhubpat"
	velesgcpapikey "github.com/google/osv-scalibr/veles/secrets/gcpapikey"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2access"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2client"
	velesgcpsak "github.com/google/osv-scalibr/veles/secrets/gcpsak"
	velesgithub "github.com/google/osv-scalibr/veles/secrets/github"
	"github.com/google/osv-scalibr/veles/secrets/gitlabpat"
	velesgrokxaiapikey "github.com/google/osv-scalibr/veles/secrets/grokxaiapikey"
	veleshashicorpvault "github.com/google/osv-scalibr/veles/secrets/hashicorpvault"
	veleshashicorpcloudplatform "github.com/google/osv-scalibr/veles/secrets/hcp"
	"github.com/google/osv-scalibr/veles/secrets/huggingfaceapikey"
	velesonepasswordkeys "github.com/google/osv-scalibr/veles/secrets/onepasswordkeys"
	velesopenai "github.com/google/osv-scalibr/veles/secrets/openai"
	velesperplexity "github.com/google/osv-scalibr/veles/secrets/perplexityapikey"
	velespostmanapikey "github.com/google/osv-scalibr/veles/secrets/postmanapikey"
	velesprivatekey "github.com/google/osv-scalibr/veles/secrets/privatekey"
	pypiapitoken "github.com/google/osv-scalibr/veles/secrets/pypiapitoken"
	velesslacktoken "github.com/google/osv-scalibr/veles/secrets/slacktoken"
	velesstripeapikeys "github.com/google/osv-scalibr/veles/secrets/stripeapikeys"
	"github.com/google/osv-scalibr/veles/secrets/tinkkeyset"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// --- Errors

	// ErrMultipleSecretLocations will be returned if multiple secret locations are set.
	ErrMultipleSecretLocations = errors.New("multiple secret locations are not supported")

	// ErrUnsupportedValidationType will be returned if the validation type is not supported.
	ErrUnsupportedValidationType = errors.New("validation type is not supported")

	// ErrUnsupportedSecretType will be returned if the secret type is not supported.
	ErrUnsupportedSecretType = errors.New("unsupported secret type")

	structToProtoValidation = map[veles.ValidationStatus]spb.SecretStatus_SecretStatusEnum{
		veles.ValidationUnspecified: spb.SecretStatus_UNSPECIFIED,
		veles.ValidationUnsupported: spb.SecretStatus_UNSUPPORTED,
		veles.ValidationFailed:      spb.SecretStatus_FAILED,
		veles.ValidationInvalid:     spb.SecretStatus_INVALID,
		veles.ValidationValid:       spb.SecretStatus_VALID,
	}

	protoToStructValidation = func() map[spb.SecretStatus_SecretStatusEnum]veles.ValidationStatus {
		m := make(map[spb.SecretStatus_SecretStatusEnum]veles.ValidationStatus)
		for k, v := range structToProtoValidation {
			m[v] = k
		}
		if len(m) != len(structToProtoValidation) {
			panic("protoToStructValidation does not contain all values from structToProtoValidation")
		}
		return m
	}()
)

// --- Struct to Proto

// SecretToProto converts a struct Secret to its proto representation.
func SecretToProto(s *inventory.Secret) (*spb.Secret, error) {
	if s == nil {
		return nil, nil
	}

	sec, err := velesSecretToProto(s.Secret)
	if err != nil {
		return nil, err
	}
	res, err := validationResultToProto(s.Validation)
	if err != nil {
		return nil, err
	}
	return &spb.Secret{
		Secret:    sec,
		Status:    res,
		Locations: secretLocationToProto(s.Location),
	}, nil
}

func velesSecretToProto(s veles.Secret) (*spb.SecretData, error) {
	switch t := s.(type) {
	case velesprivatekey.PrivateKey:
		return privatekeyToProto(t), nil
	case velesgcpsak.GCPSAK:
		return gcpsakToProto(t), nil
	case dockerhubpat.DockerHubPAT:
		return dockerHubPATToProto(t), nil
	case velesdigitalocean.DigitaloceanAPIToken:
		return digitaloceanAPIKeyToProto(t), nil
	case pypiapitoken.PyPIAPIToken:
		return pypiAPITokenToProto(t), nil
	case cratesioapitoken.CratesIOAPItoken:
		return cratesioAPITokenToProto(t), nil
	case velesslacktoken.SlackAppConfigAccessToken:
		return slackAppConfigAccessTokenToProto(t), nil
	case velesslacktoken.SlackAppConfigRefreshToken:
		return slackAppConfigRefreshTokenToProto(t), nil
	case velesslacktoken.SlackAppLevelToken:
		return slackAppLevelTokenToProto(t), nil
	case velesanthropicapikey.WorkspaceAPIKey:
		return anthropicWorkspaceAPIKeyToProto(t.Key), nil
	case velesanthropicapikey.ModelAPIKey:
		return anthropicModelAPIKeyToProto(t.Key), nil
	case velesperplexity.PerplexityAPIKey:
		return perplexityAPIKeyToProto(t), nil
	case velesgrokxaiapikey.GrokXAIAPIKey:
		return grokXAIAPIKeyToProto(t), nil
	case velesgrokxaiapikey.GrokXAIManagementKey:
		return grokXAIManagementKeyToProto(t), nil
	case velesgithub.AppRefreshToken:
		return githubAppRefreshTokenToProto(t.Token), nil
	case velesgithub.AppServerToServerToken:
		return githubAppServerToServerTokenToProto(t.Token), nil
	case velesgithub.FineGrainedPersonalAccessToken:
		return githubFineGrainedPersonalAccessTokenToProto(t.Token), nil
	case velesgithub.ClassicPersonalAccessToken:
		return githubClassicPersonalAccessTokenToProto(t.Token), nil
	case velesgithub.AppUserToServerToken:
		return githubAppUserToServerTokenToProto(t.Token), nil
	case velesgithub.OAuthToken:
		return githubOAuthTokenToProto(t.Token), nil
	case gitlabpat.GitlabPAT:
		return gitalbPatKeyToProto(t), nil
	case velesazuretoken.AzureAccessToken:
		return azureAccessTokenToProto(t), nil
	case velesazuretoken.AzureIdentityToken:
		return azureIdentityTokenToProto(t), nil
	case tinkkeyset.TinkKeySet:
		return tinkKeysetToProto(t), nil
	case velesopenai.APIKey:
		return openaiAPIKeyToProto(t.Key), nil
	case velespostmanapikey.PostmanAPIKey:
		return postmanAPIKeyToProto(t), nil
	case velespostmanapikey.PostmanCollectionToken:
		return postmanCollectionTokenToProto(t), nil
	case velesazurestorageaccountaccesskey.AzureStorageAccountAccessKey:
		return azureStorageAccountAccessKeyToProto(t), nil
	case veleshashicorpvault.Token:
		return hashicorpVaultTokenToProto(t), nil
	case veleshashicorpvault.AppRoleCredentials:
		return hashicorpVaultAppRoleCredentialsToProto(t), nil
	case velesgcpapikey.GCPAPIKey:
		return gcpAPIKeyToProto(t.Key), nil
	case velespgpass.Pgpass:
		return pgpassToProto(t), nil
	case huggingfaceapikey.HuggingfaceAPIKey:
		return huggingfaceAPIKeyToProto(t), nil
	case velesstripeapikeys.StripeSecretKey:
		return stripeSecretKeyToProto(t), nil
	case velesstripeapikeys.StripeRestrictedKey:
		return stripeRestrictedKeyToProto(t), nil
	case velesstripeapikeys.StripeWebhookSecret:
		return stripeWebhookSecretToProto(t), nil
	case gcpoauth2client.Credentials:
		return gcpOAuth2ClientCredentialsToProto(t), nil
	case gcpoauth2access.Token:
		return gcpOAuth2AccessTokenToProto(t), nil
	case velesonepasswordconnecttoken.OnePasswordConnectToken:
		return onePasswordConnectTokenToProto(t), nil
	case velesonepasswordkeys.OnePasswordSecretKey:
		return onepasswordSecretKeyToProto(t), nil
	case velesonepasswordkeys.OnePasswordServiceToken:
		return onepasswordServiceTokenToProto(t), nil
	case velesonepasswordkeys.OnePasswordRecoveryCode:
		return onepasswordRecoveryCodeToProto(t), nil
	case veleshashicorpcloudplatform.ClientCredentials:
		return hashicorpCloudPlatformCredentialsToProto(t), nil
	case veleshashicorpcloudplatform.AccessToken:
		return hashicorpCloudPlatformTokenToProto(t), nil
	case mariadb.Credentials:
		return mariadbCredentialsToProto(t), nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedSecretType, s)
	}
}

func dockerHubPATToProto(s dockerhubpat.DockerHubPAT) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_DockerHubPat_{
			DockerHubPat: &spb.SecretData_DockerHubPat{
				Pat:      s.Pat,
				Username: s.Username,
			},
		},
	}
}

func digitaloceanAPIKeyToProto(s velesdigitalocean.DigitaloceanAPIToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_Digitalocean{
			Digitalocean: &spb.SecretData_DigitalOceanAPIToken{
				Key: s.Key,
			},
		},
	}
}

func pypiAPITokenToProto(s pypiapitoken.PyPIAPIToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_Pypi{
			Pypi: &spb.SecretData_PyPIAPIToken{
				Token: s.Token,
			},
		},
	}
}

func slackAppLevelTokenToProto(s velesslacktoken.SlackAppLevelToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_SlackAppLevelToken_{
			SlackAppLevelToken: &spb.SecretData_SlackAppLevelToken{
				Token: s.Token,
			},
		},
	}
}

func slackAppConfigAccessTokenToProto(s velesslacktoken.SlackAppConfigAccessToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_SlackAppConfigAccessToken_{
			SlackAppConfigAccessToken: &spb.SecretData_SlackAppConfigAccessToken{
				Token: s.Token,
			},
		},
	}
}

func slackAppConfigRefreshTokenToProto(s velesslacktoken.SlackAppConfigRefreshToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_SlackAppConfigRefreshToken_{
			SlackAppConfigRefreshToken: &spb.SecretData_SlackAppConfigRefreshToken{
				Token: s.Token,
			},
		},
	}
}

func cratesioAPITokenToProto(s cratesioapitoken.CratesIOAPItoken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_CratesIoApiToken{
			CratesIoApiToken: &spb.SecretData_CratesIOAPIToken{
				Token: s.Token,
			},
		},
	}
}

func gcpsakToProto(sak velesgcpsak.GCPSAK) *spb.SecretData {
	sakPB := &spb.SecretData_GCPSAK{
		PrivateKeyId: sak.PrivateKeyID,
		ClientEmail:  sak.ServiceAccount,
		Signature:    sak.Signature,
	}
	if sak.Extra != nil {
		sakPB.Type = sak.Extra.Type
		sakPB.ProjectId = sak.Extra.ProjectID
		sakPB.ClientId = sak.Extra.ClientID
		sakPB.AuthUri = sak.Extra.AuthURI
		sakPB.TokenUri = sak.Extra.TokenURI
		sakPB.AuthProviderX509CertUrl = sak.Extra.AuthProviderX509CertURL
		sakPB.ClientX509CertUrl = sak.Extra.ClientX509CertURL
		sakPB.UniverseDomain = sak.Extra.UniverseDomain
		sakPB.PrivateKey = sak.Extra.PrivateKey
	}
	return &spb.SecretData{
		Secret: &spb.SecretData_Gcpsak{
			Gcpsak: sakPB,
		},
	}
}

func gcpAPIKeyToProto(key string) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GcpApiKey{
			GcpApiKey: &spb.SecretData_GCPAPIKey{
				Key: key,
			},
		},
	}
}

func anthropicWorkspaceAPIKeyToProto(key string) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_AnthropicWorkspaceApiKey{
			AnthropicWorkspaceApiKey: &spb.SecretData_AnthropicWorkspaceAPIKey{
				Key: key,
			},
		},
	}
}

func anthropicModelAPIKeyToProto(key string) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_AnthropicModelApiKey{
			AnthropicModelApiKey: &spb.SecretData_AnthropicModelAPIKey{
				Key: key,
			},
		},
	}
}

func onePasswordConnectTokenToProto(s velesonepasswordconnecttoken.OnePasswordConnectToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_OnepasswordConnectToken{
			OnepasswordConnectToken: &spb.SecretData_OnePasswordConnectToken{
				DeviceUuid:        s.DeviceUUID,
				Version:           s.Version,
				EncryptedData:     s.EncryptedData,
				EncryptionKeyId:   s.EncryptionKeyID,
				Iv:                s.IV,
				UniqueKeyId:       s.UniqueKeyID,
				VerifierSalt:      s.VerifierSalt,
				VerifierLocalHash: s.VerifierLocalHash,
			},
		},
	}
}

func perplexityAPIKeyToProto(s velesperplexity.PerplexityAPIKey) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_Perplexity{
			Perplexity: &spb.SecretData_PerplexityAPIKey{
				Key: s.Key,
			},
		},
	}
}

func grokXAIAPIKeyToProto(s velesgrokxaiapikey.GrokXAIAPIKey) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GrokXaiApiKey{
			GrokXaiApiKey: &spb.SecretData_GrokXAIAPIKey{
				Key: s.Key,
			},
		},
	}
}

func azureStorageAccountAccessKeyToProto(s velesazurestorageaccountaccesskey.AzureStorageAccountAccessKey) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_AzureStorageAccountAccessKey_{
			AzureStorageAccountAccessKey: &spb.SecretData_AzureStorageAccountAccessKey{
				Key: s.Key,
			},
		},
	}
}

func grokXAIManagementKeyToProto(s velesgrokxaiapikey.GrokXAIManagementKey) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GrokXaiManagementApiKey{
			GrokXaiManagementApiKey: &spb.SecretData_GrokXAIManagementAPIKey{
				Key: s.Key,
			},
		},
	}
}
func gitalbPatKeyToProto(s gitlabpat.GitlabPAT) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GitlabPat_{
			GitlabPat: &spb.SecretData_GitlabPat{
				Pat: s.Pat,
			},
		},
	}
}

func postmanAPIKeyToProto(s velespostmanapikey.PostmanAPIKey) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_PostmanApiKey{
			PostmanApiKey: &spb.SecretData_PostmanAPIKey{
				Key: s.Key,
			},
		},
	}
}

func postmanCollectionTokenToProto(s velespostmanapikey.PostmanCollectionToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_PostmanCollectionAccessToken_{ // wrapper type has trailing underscore
			PostmanCollectionAccessToken: &spb.SecretData_PostmanCollectionAccessToken{
				Key: s.Key,
			},
		},
	}
}

func privatekeyToProto(pk velesprivatekey.PrivateKey) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_PrivateKey_{
			PrivateKey: &spb.SecretData_PrivateKey{
				Block: pk.Block,
				Der:   pk.Der,
			},
		},
	}
}

func pgpassToProto(e velespgpass.Pgpass) *spb.SecretData {
	ePB := &spb.SecretData_Pgpass{
		Hostname: e.Hostname,
		Port:     e.Port,
		Database: e.Database,
		Username: e.Username,
		Password: e.Password,
	}

	return &spb.SecretData{
		Secret: &spb.SecretData_Pgpass_{
			Pgpass: ePB,
		},
	}
}

func githubAppRefreshTokenToProto(token string) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GithubAppRefreshToken_{
			GithubAppRefreshToken: &spb.SecretData_GithubAppRefreshToken{
				Token: token,
			},
		},
	}
}

func githubAppServerToServerTokenToProto(token string) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GithubAppServerToServerToken_{
			GithubAppServerToServerToken: &spb.SecretData_GithubAppServerToServerToken{
				Token: token,
			},
		},
	}
}

func githubAppUserToServerTokenToProto(token string) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GithubAppUserToServerToken_{
			GithubAppUserToServerToken: &spb.SecretData_GithubAppUserToServerToken{
				Token: token,
			},
		},
	}
}

func githubFineGrainedPersonalAccessTokenToProto(token string) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GithubFineGrainedPersonalAccessToken_{
			GithubFineGrainedPersonalAccessToken: &spb.SecretData_GithubFineGrainedPersonalAccessToken{
				Token: token,
			},
		},
	}
}

func githubClassicPersonalAccessTokenToProto(token string) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GithubClassicPersonalAccessToken_{
			GithubClassicPersonalAccessToken: &spb.SecretData_GithubClassicPersonalAccessToken{
				Token: token,
			},
		},
	}
}

func githubOAuthTokenToProto(token string) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GithubOauthToken{
			GithubOauthToken: &spb.SecretData_GithubOAuthToken{
				Token: token,
			},
		},
	}
}

func azureAccessTokenToProto(pk velesazuretoken.AzureAccessToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_AzureAccessToken_{
			AzureAccessToken: &spb.SecretData_AzureAccessToken{
				Token: pk.Token,
			},
		},
	}
}

func azureIdentityTokenToProto(pk velesazuretoken.AzureIdentityToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_AzureIdentityToken_{
			AzureIdentityToken: &spb.SecretData_AzureIdentityToken{
				Token: pk.Token,
			},
		},
	}
}

func tinkKeysetToProto(t tinkkeyset.TinkKeySet) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_TinkKeyset_{
			TinkKeyset: &spb.SecretData_TinkKeyset{
				Content: t.Content,
			},
		},
	}
}

func openaiAPIKeyToProto(key string) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_OpenaiApiKey{
			OpenaiApiKey: &spb.SecretData_OpenAIAPIKey{
				Key: key,
			},
		},
	}
}

func hashicorpVaultTokenToProto(s veleshashicorpvault.Token) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_HashicorpVaultToken{
			HashicorpVaultToken: &spb.SecretData_HashiCorpVaultToken{
				Token: s.Token,
			},
		},
	}
}

func hashicorpVaultAppRoleCredentialsToProto(s veleshashicorpvault.AppRoleCredentials) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_HashicorpVaultAppRoleCredentials{
			HashicorpVaultAppRoleCredentials: &spb.SecretData_HashiCorpVaultAppRoleCredentials{
				RoleId:   s.RoleID,
				SecretId: s.SecretID,
				Id:       s.ID,
			},
		},
	}
}

func huggingfaceAPIKeyToProto(s huggingfaceapikey.HuggingfaceAPIKey) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_Hugginface{
			Hugginface: &spb.SecretData_HuggingfaceAPIKey{
				Key:              s.Key,
				Role:             s.Role,
				FineGrainedScope: s.FineGrainedScope,
			},
		},
	}
}

func stripeSecretKeyToProto(s velesstripeapikeys.StripeSecretKey) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_StripeSecretKey_{
			StripeSecretKey: &spb.SecretData_StripeSecretKey{
				Key: s.Key,
			},
		},
	}
}

func stripeRestrictedKeyToProto(s velesstripeapikeys.StripeRestrictedKey) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_StripeRestrictedKey_{
			StripeRestrictedKey: &spb.SecretData_StripeRestrictedKey{
				Key: s.Key,
			},
		},
	}
}

func stripeWebhookSecretToProto(s velesstripeapikeys.StripeWebhookSecret) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_StripeWebhookSecret_{
			StripeWebhookSecret: &spb.SecretData_StripeWebhookSecret{
				Key: s.Key,
			},
		},
	}
}

func gcpOAuth2ClientCredentialsToProto(s gcpoauth2client.Credentials) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GcpOauth2ClientCredentials{
			GcpOauth2ClientCredentials: &spb.SecretData_GCPOAuth2ClientCredentials{
				Id:     s.ID,
				Secret: s.Secret,
			},
		},
	}
}

func gcpOAuth2AccessTokenToProto(s gcpoauth2access.Token) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_GcpOauth2AccessToken{
			GcpOauth2AccessToken: &spb.SecretData_GCPOAuth2AccessToken{
				Token: s.Token,
			},
		},
	}
}

func onepasswordSecretKeyToProto(s velesonepasswordkeys.OnePasswordSecretKey) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_OnepasswordSecretKey{
			OnepasswordSecretKey: &spb.SecretData_OnePasswordSecretKey{
				Key: s.Key,
			},
		},
	}
}

func onepasswordServiceTokenToProto(s velesonepasswordkeys.OnePasswordServiceToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_OnepasswordServiceToken{
			OnepasswordServiceToken: &spb.SecretData_OnePasswordServiceToken{
				Key: s.Key,
			},
		},
	}
}

func onepasswordRecoveryCodeToProto(s velesonepasswordkeys.OnePasswordRecoveryCode) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_OnepasswordRecoveryCode{
			OnepasswordRecoveryCode: &spb.SecretData_OnePasswordRecoveryCode{
				Key: s.Key,
			},
		},
	}
}

func validationResultToProto(r inventory.SecretValidationResult) (*spb.SecretStatus, error) {
	status, err := validationStatusToProto(r.Status)
	if err != nil {
		return nil, err
	}

	var lastUpdate *timestamppb.Timestamp
	if !r.At.IsZero() {
		lastUpdate = timestamppb.New(r.At)
	}

	// Prefer nil over empty proto.
	if lastUpdate == nil && status == spb.SecretStatus_UNSPECIFIED {
		return nil, nil
	}

	return &spb.SecretStatus{
		Status:      status,
		LastUpdated: lastUpdate,
	}, nil
}

func validationStatusToProto(s veles.ValidationStatus) (spb.SecretStatus_SecretStatusEnum, error) {
	v, ok := structToProtoValidation[s]
	if !ok {
		return spb.SecretStatus_UNSPECIFIED, fmt.Errorf("%w: %q", ErrUnsupportedValidationType, s)
	}
	return v, nil
}

func secretLocationToProto(filepath string) []*spb.Location {
	return []*spb.Location{
		{
			Location: &spb.Location_Filepath{
				Filepath: &spb.Filepath{
					Path: filepath,
				},
			},
		},
	}
}

// --- Proto to Struct

// SecretToStruct converts a proto Secret to its struct representation.
func SecretToStruct(s *spb.Secret) (*inventory.Secret, error) {
	if s == nil {
		return nil, nil
	}

	if len(s.GetLocations()) > 1 {
		return nil, ErrMultipleSecretLocations
	}

	sec, err := velesSecretToStruct(s.GetSecret())
	if err != nil {
		return nil, err
	}
	res, err := validationResultToStruct(s.GetStatus())
	if err != nil {
		return nil, err
	}
	var path string
	if len(s.GetLocations()) > 0 {
		path = secretLocationToStruct(s.GetLocations()[0])
	}

	return &inventory.Secret{
		Secret:     sec,
		Location:   path,
		Validation: res,
	}, nil
}

func velesSecretToStruct(s *spb.SecretData) (veles.Secret, error) {
	switch s.Secret.(type) {
	case *spb.SecretData_PrivateKey_:
		return privatekeyToStruct(s.GetPrivateKey()), nil
	case *spb.SecretData_Pgpass_:
		return pgpassToStruct(s.GetPgpass()), nil
	case *spb.SecretData_Gcpsak:
		return gcpsakToStruct(s.GetGcpsak()), nil
	case *spb.SecretData_DockerHubPat_:
		return dockerHubPATToStruct(s.GetDockerHubPat()), nil
	case *spb.SecretData_GitlabPat_:
		return gitlabPATToStruct(s.GetGitlabPat()), nil
	case *spb.SecretData_Digitalocean:
		return digitalOceanAPITokenToStruct(s.GetDigitalocean()), nil
	case *spb.SecretData_Pypi:
		return pypiAPITokenToStruct(s.GetPypi()), nil
	case *spb.SecretData_CratesIoApiToken:
		return cratesioAPITokenToStruct(s.GetCratesIoApiToken()), nil
	case *spb.SecretData_SlackAppConfigRefreshToken_:
		return slackAppConfigRefreshTokenToStruct(s.GetSlackAppConfigRefreshToken()), nil
	case *spb.SecretData_SlackAppConfigAccessToken_:
		return slackAppConfigAccessTokenToStruct(s.GetSlackAppConfigAccessToken()), nil
	case *spb.SecretData_SlackAppLevelToken_:
		return slackAppLevelTokenToStruct(s.GetSlackAppLevelToken()), nil
	case *spb.SecretData_AnthropicWorkspaceApiKey:
		return velesanthropicapikey.WorkspaceAPIKey{Key: s.GetAnthropicWorkspaceApiKey().GetKey()}, nil
	case *spb.SecretData_AnthropicModelApiKey:
		return velesanthropicapikey.ModelAPIKey{Key: s.GetAnthropicModelApiKey().GetKey()}, nil
	case *spb.SecretData_Perplexity:
		return perplexityAPIKeyToStruct(s.GetPerplexity()), nil
	case *spb.SecretData_GrokXaiApiKey:
		return velesgrokxaiapikey.GrokXAIAPIKey{Key: s.GetGrokXaiApiKey().GetKey()}, nil
	case *spb.SecretData_AzureStorageAccountAccessKey_:
		return velesazurestorageaccountaccesskeyToStruct(s.GetAzureStorageAccountAccessKey()), nil
	case *spb.SecretData_GrokXaiManagementApiKey:
		return velesgrokxaiapikey.GrokXAIManagementKey{Key: s.GetGrokXaiManagementApiKey().GetKey()}, nil
	case *spb.SecretData_GithubAppRefreshToken_:
		return velesgithub.AppRefreshToken{Token: s.GetGithubAppRefreshToken().GetToken()}, nil
	case *spb.SecretData_GithubAppServerToServerToken_:
		return velesgithub.AppServerToServerToken{Token: s.GetGithubAppServerToServerToken().GetToken()}, nil
	case *spb.SecretData_GithubFineGrainedPersonalAccessToken_:
		return velesgithub.FineGrainedPersonalAccessToken{
			Token: s.GetGithubFineGrainedPersonalAccessToken().GetToken(),
		}, nil
	case *spb.SecretData_GithubClassicPersonalAccessToken_:
		return velesgithub.ClassicPersonalAccessToken{
			Token: s.GetGithubClassicPersonalAccessToken().GetToken(),
		}, nil
	case *spb.SecretData_GithubAppUserToServerToken_:
		return velesgithub.AppUserToServerToken{
			Token: s.GetGithubAppUserToServerToken().GetToken(),
		}, nil
	case *spb.SecretData_GithubOauthToken:
		return velesgithub.OAuthToken{Token: s.GetGithubOauthToken().GetToken()}, nil
	case *spb.SecretData_AzureAccessToken_:
		return velesazuretoken.AzureAccessToken{Token: s.GetAzureAccessToken().GetToken()}, nil
	case *spb.SecretData_AzureIdentityToken_:
		return velesazuretoken.AzureIdentityToken{Token: s.GetAzureIdentityToken().GetToken()}, nil
	case *spb.SecretData_TinkKeyset_:
		return tinkkeyset.TinkKeySet{Content: s.GetTinkKeyset().GetContent()}, nil
	case *spb.SecretData_PostmanApiKey:
		return velespostmanapikey.PostmanAPIKey{
			Key: s.GetPostmanApiKey().GetKey(),
		}, nil
	case *spb.SecretData_PostmanCollectionAccessToken_:
		return velespostmanapikey.PostmanCollectionToken{
			Key: s.GetPostmanCollectionAccessToken().GetKey(),
		}, nil
	case *spb.SecretData_HashicorpVaultToken:
		return hashicorpVaultTokenToStruct(s.GetHashicorpVaultToken()), nil
	case *spb.SecretData_HashicorpVaultAppRoleCredentials:
		return hashicorpVaultAppRoleCredentialsToStruct(s.GetHashicorpVaultAppRoleCredentials()), nil
	case *spb.SecretData_GcpApiKey:
		return velesgcpapikey.GCPAPIKey{Key: s.GetGcpApiKey().GetKey()}, nil
	case *spb.SecretData_Hugginface:
		return huggingfaceAPIKeyToStruct(s.GetHugginface()), nil
	case *spb.SecretData_StripeSecretKey_:
		return velesstripeapikeys.StripeSecretKey{
			Key: s.GetStripeSecretKey().GetKey(),
		}, nil
	case *spb.SecretData_StripeRestrictedKey_:
		return velesstripeapikeys.StripeRestrictedKey{
			Key: s.GetStripeRestrictedKey().GetKey(),
		}, nil
	case *spb.SecretData_StripeWebhookSecret_:
		return velesstripeapikeys.StripeWebhookSecret{
			Key: s.GetStripeWebhookSecret().GetKey(),
		}, nil
	case *spb.SecretData_GcpOauth2ClientCredentials:
		return gcpOAuth2ClientCredentialsToStruct(s.GetGcpOauth2ClientCredentials()), nil
	case *spb.SecretData_GcpOauth2AccessToken:
		return gcpOAuth2AccessTokenToStruct(s.GetGcpOauth2AccessToken()), nil
	case *spb.SecretData_OnepasswordSecretKey:
		return velesonepasswordkeys.OnePasswordSecretKey{
			Key: s.GetOnepasswordSecretKey().GetKey(),
		}, nil
	case *spb.SecretData_OnepasswordServiceToken:
		return velesonepasswordkeys.OnePasswordServiceToken{
			Key: s.GetOnepasswordServiceToken().GetKey(),
		}, nil
	case *spb.SecretData_OnepasswordRecoveryCode:
		return velesonepasswordkeys.OnePasswordRecoveryCode{
			Key: s.GetOnepasswordRecoveryCode().GetKey(),
		}, nil
	case *spb.SecretData_OnepasswordConnectToken:
		return onePasswordConnectTokenToStruct(s.GetOnepasswordConnectToken()), nil
	case *spb.SecretData_HashicorpCloudPlatformCredentials:
		return veleshashicorpcloudplatform.ClientCredentials{
			ClientID:     s.GetHashicorpCloudPlatformCredentials().GetClientId(),
			ClientSecret: s.GetHashicorpCloudPlatformCredentials().GetClientSecret(),
		}, nil
	case *spb.SecretData_HashicorpCloudPlatformToken:
		t := s.GetHashicorpCloudPlatformToken()
		return veleshashicorpcloudplatform.AccessToken{
			Token:          t.GetToken(),
			OrganizationID: t.GetOrganizationId(),
			ProjectID:      t.GetProjectId(),
			PrincipalID:    t.GetPrincipalId(),
			PrincipalType:  t.GetPrincipalType(),
			ServiceName:    t.GetServiceName(),
			GroupIDs:       t.GetGroupIds(),
			UserID:         t.GetUserId(),
			UserEmail:      t.GetUserEmail(),
		}, nil
	case *spb.SecretData_MariaDbCredentials:
		creds := s.GetMariaDbCredentials()
		return mariadb.Credentials{
			Section:  creds.Section,
			Host:     creds.Host,
			Port:     creds.Port,
			User:     creds.User,
			Password: creds.Password,
		}, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedSecretType, s.GetSecret())
	}
}

func digitalOceanAPITokenToStruct(kPB *spb.SecretData_DigitalOceanAPIToken) velesdigitalocean.DigitaloceanAPIToken {
	return velesdigitalocean.DigitaloceanAPIToken{
		Key: kPB.GetKey(),
	}
}

func pypiAPITokenToStruct(kPB *spb.SecretData_PyPIAPIToken) pypiapitoken.PyPIAPIToken {
	return pypiapitoken.PyPIAPIToken{
		Token: kPB.GetToken(),
	}
}

func cratesioAPITokenToStruct(kPB *spb.SecretData_CratesIOAPIToken) cratesioapitoken.CratesIOAPItoken {
	return cratesioapitoken.CratesIOAPItoken{
		Token: kPB.GetToken(),
	}
}

func slackAppLevelTokenToStruct(kPB *spb.SecretData_SlackAppLevelToken) velesslacktoken.SlackAppLevelToken {
	return velesslacktoken.SlackAppLevelToken{
		Token: kPB.GetToken(),
	}
}

func slackAppConfigAccessTokenToStruct(kPB *spb.SecretData_SlackAppConfigAccessToken) velesslacktoken.SlackAppConfigAccessToken {
	return velesslacktoken.SlackAppConfigAccessToken{
		Token: kPB.GetToken(),
	}
}

func slackAppConfigRefreshTokenToStruct(kPB *spb.SecretData_SlackAppConfigRefreshToken) velesslacktoken.SlackAppConfigRefreshToken {
	return velesslacktoken.SlackAppConfigRefreshToken{
		Token: kPB.GetToken(),
	}
}

func dockerHubPATToStruct(kPB *spb.SecretData_DockerHubPat) dockerhubpat.DockerHubPAT {
	return dockerhubpat.DockerHubPAT{
		Pat:      kPB.GetPat(),
		Username: kPB.GetUsername(),
	}
}

func gitlabPATToStruct(kPB *spb.SecretData_GitlabPat) gitlabpat.GitlabPAT {
	return gitlabpat.GitlabPAT{
		Pat: kPB.GetPat(),
	}
}

func onePasswordConnectTokenToStruct(kPB *spb.SecretData_OnePasswordConnectToken) velesonepasswordconnecttoken.OnePasswordConnectToken {
	if kPB == nil {
		return velesonepasswordconnecttoken.OnePasswordConnectToken{}
	}
	return velesonepasswordconnecttoken.OnePasswordConnectToken{
		DeviceUUID:        kPB.GetDeviceUuid(),
		Version:           kPB.GetVersion(),
		EncryptedData:     kPB.GetEncryptedData(),
		EncryptionKeyID:   kPB.GetEncryptionKeyId(),
		IV:                kPB.GetIv(),
		UniqueKeyID:       kPB.GetUniqueKeyId(),
		VerifierSalt:      kPB.GetVerifierSalt(),
		VerifierLocalHash: kPB.GetVerifierLocalHash(),
	}
}

func huggingfaceAPIKeyToStruct(kPB *spb.SecretData_HuggingfaceAPIKey) huggingfaceapikey.HuggingfaceAPIKey {
	return huggingfaceapikey.HuggingfaceAPIKey{
		Key:              kPB.GetKey(),
		Role:             kPB.GetRole(),
		FineGrainedScope: kPB.GetFineGrainedScope(),
	}
}

func gcpOAuth2ClientCredentialsToStruct(kPB *spb.SecretData_GCPOAuth2ClientCredentials) gcpoauth2client.Credentials {
	return gcpoauth2client.Credentials{
		ID:     kPB.GetId(),
		Secret: kPB.GetSecret(),
	}
}

func gcpOAuth2AccessTokenToStruct(kPB *spb.SecretData_GCPOAuth2AccessToken) gcpoauth2access.Token {
	return gcpoauth2access.Token{
		Token: kPB.GetToken(),
	}
}

func gcpsakToStruct(sakPB *spb.SecretData_GCPSAK) velesgcpsak.GCPSAK {
	sak := velesgcpsak.GCPSAK{
		PrivateKeyID:   sakPB.GetPrivateKeyId(),
		ServiceAccount: sakPB.GetClientEmail(),
		Signature:      sakPB.GetSignature(),
	}
	if sakPB.GetType() != "" {
		sak.Extra = &velesgcpsak.ExtraFields{
			Type:                    sakPB.GetType(),
			ProjectID:               sakPB.GetProjectId(),
			ClientID:                sakPB.GetClientId(),
			AuthURI:                 sakPB.GetAuthUri(),
			TokenURI:                sakPB.GetTokenUri(),
			AuthProviderX509CertURL: sakPB.GetAuthProviderX509CertUrl(),
			ClientX509CertURL:       sakPB.GetClientX509CertUrl(),
			UniverseDomain:          sakPB.GetUniverseDomain(),
			PrivateKey:              sakPB.GetPrivateKey(),
		}
	}
	return sak
}

func pgpassToStruct(ePB *spb.SecretData_Pgpass) velespgpass.Pgpass {
	pgpass := velespgpass.Pgpass{
		Hostname: ePB.GetHostname(),
		Port:     ePB.GetPort(),
		Database: ePB.GetDatabase(),
		Username: ePB.GetUsername(),
		Password: ePB.GetPassword(),
	}
	return pgpass
}

func perplexityAPIKeyToStruct(kPB *spb.SecretData_PerplexityAPIKey) velesperplexity.PerplexityAPIKey {
	return velesperplexity.PerplexityAPIKey{
		Key: kPB.GetKey(),
	}
}

func velesazurestorageaccountaccesskeyToStruct(kPB *spb.SecretData_AzureStorageAccountAccessKey) velesazurestorageaccountaccesskey.AzureStorageAccountAccessKey {
	return velesazurestorageaccountaccesskey.AzureStorageAccountAccessKey{
		Key: kPB.GetKey(),
	}
}

func privatekeyToStruct(pkPB *spb.SecretData_PrivateKey) velesprivatekey.PrivateKey {
	return velesprivatekey.PrivateKey{
		Block: pkPB.GetBlock(),
		Der:   pkPB.GetDer(),
	}
}

func validationResultToStruct(r *spb.SecretStatus) (inventory.SecretValidationResult, error) {
	status, err := validationStatusToStruct(r.GetStatus())
	if err != nil {
		return inventory.SecretValidationResult{}, err
	}
	var at time.Time
	if r.GetLastUpdated() != nil {
		at = r.GetLastUpdated().AsTime()
	}
	return inventory.SecretValidationResult{
		Status: status,
		At:     at,
	}, nil
}

func validationStatusToStruct(s spb.SecretStatus_SecretStatusEnum) (veles.ValidationStatus, error) {
	v, ok := protoToStructValidation[s]
	if !ok {
		return veles.ValidationUnspecified, fmt.Errorf("%w: %q", ErrUnsupportedValidationType, s)
	}
	return v, nil
}

func secretLocationToStruct(location *spb.Location) string {
	if location.GetFilepath() != nil {
		return location.GetFilepath().GetPath()
	}
	return ""
}

func hashicorpVaultTokenToStruct(tokenPB *spb.SecretData_HashiCorpVaultToken) veleshashicorpvault.Token {
	return veleshashicorpvault.Token{
		Token: tokenPB.GetToken(),
	}
}

func hashicorpVaultAppRoleCredentialsToStruct(credsPB *spb.SecretData_HashiCorpVaultAppRoleCredentials) veleshashicorpvault.AppRoleCredentials {
	return veleshashicorpvault.AppRoleCredentials{
		RoleID:   credsPB.GetRoleId(),
		SecretID: credsPB.GetSecretId(),
		ID:       credsPB.GetId(),
	}
}

func hashicorpCloudPlatformCredentialsToProto(creds veleshashicorpcloudplatform.ClientCredentials) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_HashicorpCloudPlatformCredentials{
			HashicorpCloudPlatformCredentials: &spb.SecretData_HashiCorpCloudPlatformCredentials{
				ClientId:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
			},
		},
	}
}

func hashicorpCloudPlatformTokenToProto(token veleshashicorpcloudplatform.AccessToken) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_HashicorpCloudPlatformToken{
			HashicorpCloudPlatformToken: &spb.SecretData_HashiCorpCloudPlatformToken{
				Token:          token.Token,
				OrganizationId: token.OrganizationID,
				ProjectId:      token.ProjectID,
				PrincipalId:    token.PrincipalID,
				PrincipalType:  token.PrincipalType,
				ServiceName:    token.ServiceName,
				GroupIds:       token.GroupIDs,
				UserId:         token.UserID,
				UserEmail:      token.UserEmail,
			},
		},
	}
}
func mariadbCredentialsToProto(t mariadb.Credentials) *spb.SecretData {
	return &spb.SecretData{
		Secret: &spb.SecretData_MariaDbCredentials{
			MariaDbCredentials: &spb.SecretData_MariaDBCredentials{
				Host:     t.Host,
				Port:     t.Port,
				User:     t.User,
				Password: t.Password,
				Section:  t.Section,
			},
		},
	}
}
