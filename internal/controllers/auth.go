package controllers

import (
	"baas-user/internal/configs"
	"baas-user/internal/controllers/inputs"
	"baas-user/internal/controllers/outputs"
	"baas-user/internal/services"
	"context"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/danielgtaylor/huma/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type AuthController struct {
	provider  *oidc.Provider
	config    oauth2.Config
	verifier  *oidc.IDTokenVerifier
	appConfig *configs.Config
	service   *services.Service
	// logger    *httplog.Logger
}

func InitAuthController(ctx context.Context, appConfig *configs.Config, service *services.Service) *AuthController {
	provider, err := oidc.NewProvider(ctx, appConfig.Keycloak.Issuer)

	if err != nil {
		log.Panicf("Failed to create OIDC provider: %+v", err)
	}

	config := oauth2.Config{
		ClientID:     appConfig.Keycloak.ClientId,
		ClientSecret: appConfig.Keycloak.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  appConfig.Keycloak.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: appConfig.Keycloak.ClientId})

	controller := &AuthController{}
	controller.provider = provider
	controller.config = config
	controller.verifier = verifier
	controller.appConfig = appConfig
	controller.service = service

	return controller
}

func authMiddleware(ctx huma.Context, next func(huma.Context)) {

	ctx = huma.WithValue(ctx, "TLS", ctx.TLS() != nil)

	next(ctx)
}

func (ac *AuthController) RegisterAuthAPIs(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "auth-login",
		Method:      http.MethodGet,
		Path:        "/auth/login",
		Summary:     "Login",
		Description: "Login",
		Tags:        []string{"Auth"},
		Middlewares: huma.Middlewares{authMiddleware},
	}, func(ctx context.Context, input *inputs.AuthLoginInput) (*outputs.AuthLoginOutput, error) {
		resp := &outputs.AuthLoginOutput{}

		state := uuid.New().String()
		nonce := uuid.New().String()

		tls, ok := ctx.Value("TLS").(bool)
		if !ok {
			resp.Status = 500
			return resp, nil
		}

		resp.RedirectCookie = &http.Cookie{Name: "redirect_url", Value: input.RedirectURL, Path: "/", HttpOnly: true, Secure: tls}
		resp.StateCookie = &http.Cookie{Name: "state", Value: state, Path: "/", HttpOnly: true, Secure: tls}
		resp.NonceCookie = &http.Cookie{Name: "nonce", Value: nonce, Path: "/", HttpOnly: true, Secure: tls}

		resp.Status = http.StatusFound
		resp.Url = ac.config.AuthCodeURL(state, oidc.Nonce(nonce))
		return resp, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "auth-callback",
		Method:      http.MethodGet,
		Path:        "/auth/callback",
		Summary:     "Callback",
		Description: "Callback",
		Tags:        []string{"Auth"},
		Middlewares: huma.Middlewares{authMiddleware},
	}, func(ctx context.Context, input *inputs.AuthCallbackInput) (*outputs.AuthCallbackOutput, error) {
		resp := &outputs.AuthCallbackOutput{}

		if input.State != input.StateCookie {
			// resp.Status = http.StatusBadRequest
			resp.Status = http.StatusOK
			resp.Body.Message = "state did not match"
			return resp, nil
		}

		oauth2Token, err := ac.config.Exchange(ctx, input.Code)
		if err != nil {
			// resp.Status = http.StatusInternalServerError
			resp.Status = http.StatusOK
			resp.Body.Message = "Failed to exchange token: " + err.Error()
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			// resp.Status = http.StatusInternalServerError
			resp.Status = http.StatusOK
			resp.Body.Message = "No id_token field in oauth2 token."
			return resp, nil
		}
		idToken, err := ac.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			resp.Status = http.StatusOK
			resp.Body.Message = "Failed to verify ID Token: " + err.Error()
			return resp, nil
		}

		if idToken.Nonce != input.NonceCookie {
			resp.Status = http.StatusOK
			resp.Body.Message = "nonce did not match"
			return resp, nil
		}

		var idTokenClaims struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		if err := idToken.Claims(&idTokenClaims); err != nil {
			// resp.Status = http.StatusInternalServerError
			resp.Status = http.StatusOK
			resp.Body.Message = err.Error()
			return resp, nil
		}

		claims := jwt.MapClaims{
			"sub":   idToken.Subject,
			"iss":   ac.appConfig.Jwt.Issuer,
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Duration(ac.appConfig.Jwt.ExpireIn) * time.Second).Unix(),
			"name":  idTokenClaims.Name,
			"email": idTokenClaims.Email,
		}

		sub, err := uuid.Parse(idToken.Subject)
		if err != nil {
			resp.Status = http.StatusInternalServerError
			resp.Body.Message = err.Error()
			return resp, nil
		}

		if err = ac.service.CreateUserWithUUID(sub, idTokenClaims.Email); err != nil {
			// resp.Status = http.StatusInternalServerError
			resp.Status = http.StatusOK
			resp.Body.Message = "Failed to create user: " + err.Error()
			return resp, nil
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signedToken, err := token.SignedString(ac.appConfig.Jwt.PrivateKey)

		if err != nil {
			// resp.Status = http.StatusInternalServerError
			resp.Status = http.StatusOK
			resp.Body.Message = "Failed to sign token: " + err.Error()
			return resp, nil
		}

		tls := ctx.Value("TLS").(bool)

		resp.Status = http.StatusFound
		resp.Body.Ok = true
		resp.TokenCookie = &http.Cookie{Name: "token", Value: signedToken, Path: "/", HttpOnly: true, Secure: tls}
		resp.Url = input.RedirectURL

		return resp, nil
	})
}
