package handlers

const (
	localPort                  = "9001"
	logInfo                    = 1
	logWarn                    = 2
	logErr                     = 3
	ERROR1                     = "You+have+been+left+in+the+dark:+"
	ERROR2                     = "You+have+been+ghosted+by+the+system:+"
	invalidRequestMethod       = "Invalid+request+method"
	errorParsingData           = "Error+parsing+form+data"
	profileAuthenticationError = "Error+authenticating+profile"
	profileNotFound            = "Profile+does+not+exist"
	profileNameAlreadyExists   = "Profile+name+already+exists.+Please+create+a+different+profile+name."
	profileEmailAlreadyExists  = "Email+already+exists.+Only+one+profile+is+permitted+for+each+email."
	newProfileError            = "Error+creating+new+profile"
	emailNewProfileError       = "New+profile+created+but+failed+to+send+email+notification+for+new+profile.+Please+contact+support:+ghostedjobsuk@gmail.com"
	errorUpdatingSessionTokens = "Error+updating+profile+session+tokens"
	sessionNotFound            = "Session+token+not+found+for+profile"
	sessionCookieError         = "Error+setting+session+cookie"
	sessionCsrfCookieError     = "Error+setting+csrf+cookie"
	reviewsError               = "Error+getting+all+reviews"
	reviewsNotFound            = "Review+not+found"
	decryptCompanyNameError    = "Error+decrypting+company+name"
	decryptRecruiterNameError  = "Error+decrypting+recruiter+name"
	decryptManagerNameError    = "Error+decrypting+manager+name"
	decryptReviewContentError  = "Error+decrypting+manager+name"
	decryptProfileNameError    = "Error+decryptng+profile+name"
	logoutError                = "Error+logging+out+profile"
)

type ViewGhostedReviews struct {
	CompanyName     string `json:"company_name"`
	InteractionType string `json:"interaction_type"`
	RecruiterName   string `json:"recruiter_name"`
	ManagerName     string `json:"manager_name"`
	ReviewRating    string `json:"review_rating"`
	ReviewContent   string `json:"review_content"`
	CreatedAt       string `json:"created_at"`
	ProfileName     string `json:"profile_name"`
}

type ErrorMessages struct {
	// HTTP server error messages
	BadRequestError     string
	NotFoundError       string
	AuthenticationError string
	InternalServerError string
	CookieError         string
	ValidationError     string
	ReviewsError        string
	RecruiterNameError  string
	CompanyNameError    string
	ManagerNameError    string
	ReviewContentError  string
	ProfileNameError    string
	LogoutError         string
}
