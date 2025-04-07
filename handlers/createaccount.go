package handlers

import (
	"fmt"
	"net/http"

	"github.com/Bevs-n-Devs/ghostedjobs/db"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
)

func CreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logs.Logs(logErr, fmt.Sprintf("Invalid request method: %s. Redirecting back to home page", r.Method))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	err := r.ParseForm()
	if err != nil {
		logs.Logs(logErr, "Error parsing form data: "+err.Error())
		http.Error(w, "Error parsing form data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// extract form data
	profileName := r.FormValue("profileName")
	userEmail := r.FormValue("userEmail")
	userPassword := r.FormValue("userPassword")

	// validate profile name & email
	profileNameExists := db.CheckProfileName(profileName)
	if profileNameExists {
		logs.Logs(logErr, "New profile could not be created. Profile name already exists in the database: "+profileName)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	profileEmailExists := db.CheckProfileEmail(userEmail)
	if profileEmailExists {
		logs.Logs(logErr, "New profile could not be created. Email already exists in the database: "+userEmail)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// create new profile
	err = db.CreateNewProfile(profileName, userEmail, userPassword)
	if err != nil {
		logs.Logs(logErr, "Error creating new profile: "+err.Error())
		http.Error(w, "Error creating new profile: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO: Send confirmation email email to user

	// redirect to login page
	logs.Logs(logInfo, "New profile created successfully")
	http.Redirect(w, r, "/#summonYourSpirit", http.StatusSeeOther) // redirects the user to the login section of the home page
}
