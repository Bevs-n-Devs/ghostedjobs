package db

import (
	"database/sql"
)

const (
	logWarning = 2
	logErr     = 3
	logDb      = 4
	logDbErr   = 5
)

var (
	db *sql.DB // global variable to hold the database connection
)

type GhostedReviews struct {
	CompanyName     []byte `json:"company_name"`
	InteractionType string `json:"interaction_type"`
	RecruiterName   []byte `json:"recruiter_name"`
	ManagerName     []byte `json:"manager_name"`
	ReviewRating    string `json:"review_rating"`
	ReviewContent   []byte `json:"review_content"`
	CreatedAt       string `json:"created_at"`
	ProfileName     []byte `json:"profile_name"`
}
