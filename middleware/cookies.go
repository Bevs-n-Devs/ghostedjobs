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
		Expires:  expiryTime,
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
		Expires:  expiryTime,
		HttpOnly: false,
		Path:     "/reviews",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func SearchCompanySessionCookie(w http.ResponseWriter, sessionToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiryTime,
		HttpOnly: true,
		Path:     "/search-company",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func SearchCompanyCSRFTokenCookie(w http.ResponseWriter, csrfToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expiryTime,
		HttpOnly: false,
		Path:     "/search-company",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func SearchInteractionTypeSessionCookie(w http.ResponseWriter, sessionToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiryTime,
		HttpOnly: true,
		Path:     "/search-interaction",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func SearchInteractionTypeCSRFTokenCookie(w http.ResponseWriter, csrfToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expiryTime,
		HttpOnly: false,
		Path:     "/search-interaction",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func SearchReviewRatingSessionCookie(w http.ResponseWriter, sessionToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiryTime,
		HttpOnly: true,
		Path:     "/search-rating",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func SearchReviewRatingCSRFTokenCookie(w http.ResponseWriter, csrfToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expiryTime,
		HttpOnly: false,
		Path:     "/search-rating",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func LogoutProfileSessionCookie(w http.ResponseWriter, sessionToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiryTime,
		HttpOnly: true,
		Path:     "/logout",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func LogoutProfileCSRFTokenCookie(w http.ResponseWriter, csrfToken string, expiryTime time.Time) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expiryTime,
		HttpOnly: false,
		Path:     "/logout",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func DeleteProfileSessionCookie(w http.ResponseWriter) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func DeleteProfileCSRFCookie(w http.ResponseWriter) bool {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	return true
}
