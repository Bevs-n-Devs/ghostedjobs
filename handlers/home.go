package handlers

import (
	"net/http"

	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/tmpl"
)

func Home(w http.ResponseWriter, r *http.Request) {
	// get any error messages
	badRequestError := r.URL.Query().Get("badRequest")
	notFoundError := r.URL.Query().Get("notFound")
	authenticationError := r.URL.Query().Get("authenticationError")
	internalServerError := r.URL.Query().Get("internalServerError")

	data := ErrorMessages{
		BadRequestError:     badRequestError,
		NotFoundError:       notFoundError,
		AuthenticationError: authenticationError,
		InternalServerError: internalServerError,
	}

	err := tmpl.Templates.ExecuteTemplate(w, "home.html", data)
	if err != nil {
		logs.Logs(logErr, "Unable to load home page: "+err.Error())
		http.Error(w, "Unable to load home page: "+err.Error(), http.StatusInternalServerError)
	}
}
