package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	BaseUri     string
	LoginConfig oauth2.Config
}

var AuthConfig Config

func InitializeAuthCodeFlow(context context.Context, clientID string, authProviderUrl string, redirectUrl string) error {
	config, err := BuildAuthCodeFlowConfig(context, clientID, authProviderUrl, redirectUrl)
	if err != nil {
		return err
	}
	AuthConfig = *config
	return nil
}

func InitializeDeviceCodeFlow(context context.Context, clientID string, authProviderUrl string) error {
	config, err := BuildDeviceCodeConfig(context, clientID, authProviderUrl)
	if err != nil {
		return err
	}
	AuthConfig = *config
	return nil
}

func BuildDeviceCodeConfig(context context.Context, clientID string, authProviderUrl string) (*Config, error) {
	provider, err := oidc.NewProvider(context, authProviderUrl)
	if err != nil {
		return nil, fmt.Errorf("could not load OIDC configuration: %w", err)
	}

	config := &Config{
		BaseUri: authProviderUrl,
		LoginConfig: oauth2.Config{
			ClientID: clientID,
			Endpoint: provider.Endpoint(),
			Scopes:   []string{"profile", "email", oidc.ScopeOpenID},
		},
	}
	return config, nil
}

func BuildAuthCodeFlowConfig(context context.Context, clientID string, authProviderUrl string, redirectUrl string) (*Config, error) {
	provider, err := loadOIDCConfig(context, authProviderUrl)
	if err != nil {
		return nil, fmt.Errorf("could not load OIDC configuration: %w", err)
	}

	config := &Config{
		LoginConfig: oauth2.Config{
			ClientID:    clientID,
			Endpoint:    provider.Endpoint(),
			RedirectURL: redirectUrl,
			Scopes:      []string{"profile", "email", oidc.ScopeOpenID},
		},
		BaseUri: authProviderUrl,
	}
	return config, nil
}

func loadOIDCConfig(context context.Context, authProviderUrl string) (*oidc.Provider, error) {
	retries := 5
	var provider *oidc.Provider
	var err error
	i := 0
	for i < retries {
		provider, err = oidc.NewProvider(context, authProviderUrl)
		if err != nil {
			// TODO: Real retries/backoff
			slog.Warn("could not load OIDC config", "attempt", i+1, "url", authProviderUrl, "err", err)
			i++
			if i < retries {
				time.Sleep(time.Second * 10)
			}
		} else {
			break
		}
	}

	if err != nil {
		return nil, err
	}
	return provider, nil
}
