package middleware

import (
	"net/http"
	"time"
)

func ProfileDashboardSessionCookie(w http.ResponseWriter, sessionToken string, expiryTime time.Time) bool {
	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiryTime,
		HttpOnly: true,
		Path:     "/dashboard",
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
	return true
}

func ProfileDashboardCSRFTokenCookie(w http.ResponseWriter, csrfToken string, expiryTime time.Time) bool {
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expiryTime,
		HttpOnly: false,
		Path:     "/dashboard",
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
	return true
}

func CreateNewReviewSessionCookie(w http.ResponseWriter, sessionToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiryTime,
		HttpOnly: true,
		Path:     "/create-review",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func CreateNewReviewCSRFTokenCookie(w http.ResponseWriter, csrfToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expiryTime,
		HttpOnly: false,
		Path:     "/create-review",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func ViewReviewSessionCookie(w http.ResponseWriter, sessionToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiryTime.Add(5 * time.Minute),
		HttpOnly: true,
		Path:     "/reviews",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func ViewReviewCSRFTokenCookie(w http.ResponseWriter, csrfToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expiryTime.Add(5 * time.Minute),
		HttpOnly: false,
		Path:     "/reviews",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}
