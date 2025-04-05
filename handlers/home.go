package handlers

import (
	"net/http"

	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/tmpl"
)

func Home(w http.ResponseWriter, r *http.Request) {
	err := tmpl.Templates.ExecuteTemplate(w, "home.html", nil)
	if err != nil {
		logs.Logs(logErr, "Unable to load home page: "+err.Error())
		http.Error(w, "Unable to load home page: "+err.Error(), http.StatusInternalServerError)
	}
}
