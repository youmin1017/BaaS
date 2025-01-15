package outputs

import "net/http"

type AuthLoginOutput struct {
	Status         int
	Url            string       `header:"Location"`
	NonceCookie    *http.Cookie `header:"Set-Cookie"`
	StateCookie    *http.Cookie `header:"Set-Cookie"`
	RedirectCookie *http.Cookie `header:"Set-Cookie"`
}

type AuthCallbackOutput struct {
	Status      int
	Url         string       `header:"Location"`
	TokenCookie *http.Cookie `header:"Set-Cookie"`
	Body        struct {
		Message string `json:"message"`
		Ok      bool   `json:"ok" doc:"true if the request was successful"`
	}
}
