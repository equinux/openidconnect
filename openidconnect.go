// Copyright 2015 equinux AG. All rights reserved.

// Package openidconnect uses oauth2 to provide openid connect
// functionality. It is currently just a simple extension to
// the oauth2 protocol with an added id token.
package openidconnect

import (
	"net/url"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/equinux/openidconnect/internal"
)

// Config for OpenID Connect with added public key
type Config struct {
	oauth2.Config

	PublicKey string
}

// Token is the oauth2 token extended with the IDToken
type Token struct {
	oauth2.Token

	IDToken string `json:"id_token"`
}

// Exchange converts an authorization code into a token.
func (c Config) Exchange(ctx context.Context, code string) (*Token, error) {
	internalToken, err := internal.RetrieveToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.TokenURL, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": internal.CondVal(c.RedirectURL),
		"scope":        internal.CondVal(strings.Join(c.Scopes, " ")),
	})
	if err != nil {
		return nil, err
	}
	token := tokenFromInternal(internalToken)

	return token, nil
}

func tokenFromInternal(t *internal.Token) *Token {
	if t == nil {
		return nil
	}
	var idToken = ""
	switch item := t.Raw.(type) {
	case map[string]interface{}:
		switch i := item["id_token"].(type) {
		case string:
			idToken = i
		}
	}
	return &Token{
		Token: oauth2.Token{
			AccessToken:  t.AccessToken,
			TokenType:    t.TokenType,
			RefreshToken: t.RefreshToken,
			Expiry:       t.Expiry,
		},
		IDToken: idToken,
	}
}
