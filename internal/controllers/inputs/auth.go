package inputs

type AuthLoginInput struct {
	RedirectURL string `query:"redirect_url" example:"http://example.com" doc:"Redirect URL"`
}

type AuthCallbackInput struct {
	StateCookie string `cookie:"state" format:"uuid" example:"123e4567-e89b-12d3-a456-426614174000" doc:"State"`
	NonceCookie string `cookie:"nonce" format:"uuid" example:"123e4567-e89b-12d3-a456-426614174000" doc:"Nonce"`
	RedirectURL string `cookie:"redirect_url" example:"http://example.com" doc:"Redirect URL"`
	State       string `query:"state" format:"uuid" example:"123e4567-e89b-12d3-a456-426614174000" doc:"State"`
	Code        string `query:"code" example:"code" doc:"Code"`
}
