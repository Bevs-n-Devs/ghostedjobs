package handlers

import (
	"fmt"
	"net/http"

	"github.com/Bevs-n-Devs/ghostedjobs/db"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/middleware"
	"github.com/Bevs-n-Devs/ghostedjobs/tmpl"
	"github.com/Bevs-n-Devs/ghostedjobs/utils"
)

func SearchCompany(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logs.Logs(logErr, "Invalid request method for GHOSTED! search engine: "+r.Method)
		http.Redirect(w, r, fmt.Sprintf("/?badRequest=%s%s", ERROR2, invalidRequestMethod), http.StatusSeeOther)
		return
	}

	sessionToken, err := utils.CheckSessionToken(r)
	if err != nil {
		logs.Logs(logErr, "Session token not found for search engine: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionNotFound), http.StatusSeeOther)
		return
	}
	logs.Logs(logInfo, "Session token: "+sessionToken.Value)

	// validate authorisation request
	err = middleware.AuthenticateProfileRequest(r)
	if err != nil {
		logs.Logs(logErr, "Invalid request method for search engine: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, invalidRequestMethod), http.StatusSeeOther)
		return
	}

	// get hash email from session token
	hashEmail, err := db.GetHashEmailFromSessionToken(sessionToken.Value)
	if err != nil {
		logs.Logs(logErr, "Session token not found for search engine: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR1, sessionNotFound), http.StatusSeeOther)
		return
	}

	newSessionToken, newCsrfToken, newExpiryTime, err := db.UpdateProfileSessionTokens(hashEmail)
	if err != nil {
		logs.Logs(logErr, "Error updating session tokens for search engine: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, errorUpdatingSessionTokens), http.StatusSeeOther)
		return
	}

	// TODO! Set cookies for each available page
	createProfileDashboardSessionCookie := middleware.ProfileDashboardSessionCookie(w, newSessionToken, newExpiryTime)
	if !createProfileDashboardSessionCookie {
		logs.Logs(logErr, "Error creating profile dashboard session cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCookieError), http.StatusSeeOther)
		return
	}
	createProfileDashboardCSRFTokenCookie := middleware.ProfileDashboardCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createProfileDashboardCSRFTokenCookie {
		logs.Logs(logErr, "Error creating profile dashboard CSRF token cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCsrfCookieError), http.StatusSeeOther)
		return
	}

	createNewReviewSessionCookie := middleware.CreateNewReviewSessionCookie(w, newSessionToken, newExpiryTime)
	if !createNewReviewSessionCookie {
		logs.Logs(logErr, "Error creating new review session cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCookieError), http.StatusSeeOther)
		return
	}
	createNewReviewCSRFTokenCookie := middleware.CreateNewReviewCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createNewReviewCSRFTokenCookie {
		logs.Logs(logErr, "Error creating new review CSRF token cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCsrfCookieError), http.StatusSeeOther)
		return
	}

	createViewReviewSessionCookie := middleware.ViewReviewSessionCookie(w, newSessionToken, newExpiryTime)
	if !createViewReviewSessionCookie {
		logs.Logs(logErr, "Error creating view review session cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCookieError), http.StatusSeeOther)
		return
	}
	createViewReviewCSRFTokenCookie := middleware.ViewReviewCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createViewReviewCSRFTokenCookie {
		logs.Logs(logErr, "Error creating view review CSRF token cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCsrfCookieError), http.StatusSeeOther)
		return
	}

	createLogoutProfileSessionCookie := middleware.LogoutProfileSessionCookie(w, newSessionToken, newExpiryTime)
	if !createLogoutProfileSessionCookie {
		logs.Logs(logErr, "Error creating logout profile session cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCookieError), http.StatusSeeOther)
		return
	}
	createLogoutProfileCSRFTokenCookie := middleware.LogoutProfileCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createLogoutProfileCSRFTokenCookie {
		logs.Logs(logErr, "Error creating logout profile CSRF token cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCsrfCookieError), http.StatusSeeOther)
		return
	}

	// get form data
	err = r.ParseForm()
	if err != nil {
		logs.Logs(logErr, "Error parsing form data: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/reviews?companyNameError=%s%s", ERROR2, errorParsingData), http.StatusSeeOther)
		return
	}

	// extract data
	companyName := r.FormValue("companyName")

	reviewsByCompany, err := db.GetAllReviewsByCompanyName(companyName)
	if err != nil {
		logs.Logs(logErr, "Error getting reviews by company name: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/reviews?reviewsError=%s%s", ERROR2, reviewsNotFound), http.StatusSeeOther)
		return
	}

	showCompanyReviews := []ViewGhostedReviews{}
	for index := range reviewsByCompany {
		var convertData ViewGhostedReviews

		convertData.InteractionType = reviewsByCompany[index].InteractionType
		convertData.ReviewRating = reviewsByCompany[index].ReviewRating
		convertData.CreatedAt = reviewsByCompany[index].CreatedAt

		// decrypt data
		companyName, err := utils.Decrypt(reviewsByCompany[index].CompanyName)
		if err != nil {
			logs.Logs(logErr, "Error decrypting company name: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/reviews?companyNameError=%s%s", ERROR2, decryptCompanyNameError), http.StatusSeeOther)
			return
		}
		convertData.CompanyName = string(companyName)

		recruiterName, err := utils.Decrypt(reviewsByCompany[index].RecruiterName)
		if err != nil {
			logs.Logs(logErr, "Error decrypting recruiter name: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/reviews?recruiterNameError=%s%s", ERROR2, decryptRecruiterNameError), http.StatusSeeOther)
			return
		}
		convertData.RecruiterName = string(recruiterName)

		managerName, err := utils.Decrypt(reviewsByCompany[index].ManagerName)
		if err != nil {
			logs.Logs(logErr, "Error decrypting manager name: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/reviews?managerNameError=%s%s", ERROR2, decryptManagerNameError), http.StatusSeeOther)
			return
		}
		convertData.ManagerName = string(managerName)

		reviewContent, err := utils.Decrypt(reviewsByCompany[index].ReviewContent)
		if err != nil {
			logs.Logs(logErr, "Error decrypting review content: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/reviews?reviewContentError=%s%s", ERROR2, decryptReviewContentError), http.StatusSeeOther)
			return
		}
		convertData.ReviewContent = string(reviewContent)

		profileName, err := utils.Decrypt(reviewsByCompany[index].ProfileName)
		if err != nil {
			logs.Logs(logErr, "Error decrypting profile name: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/reviews?profileNameError=%s%s", ERROR2, decryptProfileNameError), http.StatusSeeOther)
			return
		}
		convertData.ProfileName = string(profileName)

		// add data to showCompanyReviews slice
		showCompanyReviews = append(showCompanyReviews, convertData)
	}

	// handle page errors
	reviewsError := r.URL.Query().Get("reviewsError")
	companyNameError := r.URL.Query().Get("companyNameError")
	recruiterNameError := r.URL.Query().Get("recruiterNameError")
	managerNameError := r.URL.Query().Get("managerNameError")
	reviewContentError := r.URL.Query().Get("reviewContentError")
	profileNameError := r.URL.Query().Get("profileNameError")

	// create struct in order to pass data to template
	data := struct {
		Reviews []ViewGhostedReviews
		Errors  ErrorMessages
	}{
		Reviews: showCompanyReviews,
		Errors: ErrorMessages{
			ReviewsError:       reviewsError,
			CompanyNameError:   companyNameError,
			RecruiterNameError: recruiterNameError,
			ManagerNameError:   managerNameError,
			ReviewContentError: reviewContentError,
			ProfileNameError:   profileNameError,
		},
	}

	err = tmpl.Templates.ExecuteTemplate(w, "reviews.html", data)
	if err != nil {
		logs.Logs(logErr, "Unable to load review page: "+err.Error())
		http.Error(w, "Unable to load review page: "+err.Error(), http.StatusInternalServerError)
	}
}
