package middleware

import (
	"net/http"
	"time"
)

func ProfileDashboardSessionCookie(w http.ResponseWriter, sessionToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiryTime,
		HttpOnly: true,
		Path:     "/dashboard",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func ProfileDashboardCSRFTokenCookie(w http.ResponseWriter, csrfToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expiryTime,
		HttpOnly: false,
		Path:     "/dashboard",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}
