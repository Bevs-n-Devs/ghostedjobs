package handlers

const (
	localPort = "9001"
	logInfo   = 1
	logWarn   = 2
	logErr    = 3
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
