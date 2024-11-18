package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"math/big"
	"net/http"
	"time"
)

const host = "https://25e7e06def7f.ngrok.app"

var privateKey *rsa.PrivateKey

// Initialize Fosite provider
func newOAuth2Provider() fosite.OAuth2Provider {
	// This secret is being used to sign access and refresh tokens as well as
	// authorization codes. It must be exactly 32 bytes long.
	var secret = []byte("BimPY6GrQCX2cYPJi3b1jxxAlci2/cS")
	bytes, err := bcrypt.GenerateFromPassword([]byte(secret), 14)

	// In-memory storage for simplicity
	store := storage.NewMemoryStore()
	// Example client (you can fetch these from a database instead)
	store.Clients["example-client"] = &fosite.DefaultClient{
		ID:            "example-client",
		Secret:        bytes,
		RedirectURIs:  []string{host + "/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
	}

	// Generate an RSA key for signing JWTs (ID tokens)
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

	// Setup the Fosite provider
	config := &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		GlobalSecret:        bytes,
	}
	/*	oauth2Provider := fosite.NewOAuth2Provider(
		store,
		config,
	)*/
	oauth2Provider := compose.ComposeAllEnabled(config, store, privateKey)

	// Add OpenID Connect handlers
	//oauth2Provider.AuthorizeEndpointHandlers.Append(openid.NewOpenIDConnectExplicitHandler())
	//	oauth2Provider.TokenEndpointHandlers.Append(openid.NewOpenIDConnectTokenHandler())

	return oauth2Provider
}

func main() {
	oauth2Provider := newOAuth2Provider()

	// /authorize endpoint
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		var mySession = &openid.DefaultSession{
			Username: "raul",
			Subject:  "sub",
			Claims: &jwt.IDTokenClaims{
				Issuer:      host,
				Subject:     "raul",
				Audience:    []string{"https://my-client.my-application.com"},
				ExpiresAt:   time.Now().Add(time.Hour * 6),
				IssuedAt:    time.Now(),
				RequestedAt: time.Now(),
				AuthTime:    time.Now(),
				Extra: map[string]interface{}{
					"groups": []string{"admin", "dev"},
				},
			},
			Headers: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
		} // Customize this session for your needs

		// Handle authorization request
		authorizeRequest, err := oauth2Provider.NewAuthorizeRequest(ctx, r)
		if err != nil {
			oauth2Provider.WriteAuthorizeError(ctx, w, authorizeRequest, err)
			return
		}
		authorizeRequest.GrantScope("openid")
		authorizeRequest.GrantScope("email")
		authorizeRequest.GrantScope("profile")

		// Validate client and issue an authorization code
		response, err := oauth2Provider.NewAuthorizeResponse(ctx, authorizeRequest, mySession)
		if err != nil {
			oauth2Provider.WriteAuthorizeError(ctx, w, authorizeRequest, err)
			return
		}

		oauth2Provider.WriteAuthorizeResponse(ctx, w, authorizeRequest, response)
	})

	// /token endpoint
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		var mySession = &openid.DefaultSession{}

		// Handle token request
		accessRequest, err := oauth2Provider.NewAccessRequest(ctx, r, mySession)
		if err != nil {
			oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		response, err := oauth2Provider.NewAccessResponse(ctx, accessRequest)
		if err != nil {
			oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		oauth2Provider.WriteAccessResponse(ctx, w, accessRequest, response)
	})

	// /.well-known/openid-configuration endpoint
	http.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"issuer": "` + host + `",
			"authorization_endpoint": "` + host + `/authorize",
			"token_endpoint": "` + host + `/token",
			"jwks_uri": "` + host + `/.well-known/jwks.json",
			"response_types_supported": ["code"],
			"subject_types_supported": ["public"],
			"id_token_signing_alg_values_supported": ["RS256"]
		}`))
	})

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pubKey := privateKey.PublicKey
		n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())

		jwks := JWKS{
			Keys: []JWK{
				{
					Kty: "RSA",
					Use: "sig",
					Kid: "unique-key-id", // Replace with a unique identifier for your key
					N:   n,
					E:   e,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, "failed to encode JWKS", http.StatusInternalServerError)
		}

	})

	// Start HTTP server
	log.Println("Server is running at " + host)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type (e.g., RSA)
	Use string `json:"use"` // Key Usage (e.g., sig)
	Kid string `json:"kid"` // Key ID
	N   string `json:"n"`   // Modulus
	E   string `json:"e"`   // Exponent
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}
