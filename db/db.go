package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	_ "embed"

	"github.com/Bevs-n-Devs/ghostedjobs/env"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/utils"
	_ "github.com/lib/pq"
)

/*
ConnectDB connects to the PostgreSQL database via the DATABASE_URL environment
variable. If this variable is empty, it attempts to load the environment
variables from the .env file. The function logs the progress of the
connection attempt and returns an error if the connection cannot be
established.

Returns:

- error: An error object if the connection cannot be established.
*/
func ConnectDB() error {
	var err error

	// connect to database via environment variable
	if os.Getenv("DATABASE_URL") == "" {
		logs.Logs(logWarning, "Could not get database URL from hosting platform. Loading from .env file...")
		err := env.LoadEnv("env/.env")
		if err != nil {
			logs.Logs(logErr, fmt.Sprintf("Could not load environment variables from .env file: %s", err.Error()))
			return err
		}
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		logs.Logs(logDbErr, "Database URL is empty!")
		return fmt.Errorf("database URL is empty")
	}

	logs.Logs(logDb, "Connecting to database...")
	db, err = sql.Open("postgres", dbURL) // open db connection from global db variable
	if err != nil {
		logs.Logs(logDbErr, fmt.Sprintf("Could not connect to database: %s", err.Error()))
		return err
	}

	// verify connection
	logs.Logs(logDb, "Verifying database connection...")
	if db == nil {
		logs.Logs(logDbErr, "Database connection is empty!")
		return errors.New("database connection not established")
	}
	err = db.Ping()
	if err != nil {
		logs.Logs(logDbErr, fmt.Sprintf("Cannot ping database: %s", err.Error()))
		return err
	}
	logs.Logs(logDb, "Database connection established.")
	return nil
}

func CheckProfileName(profileName string) bool {
	hashProfileName := utils.HashData(profileName)

	query := `
    SELECT hash_profile_name
    FROM ghostedjobs_profile
    WHERE hash_profile_name = $1
    `
	rows, err := db.Query(query, hashProfileName)
	if err != nil {
		logs.Logs(logErr, "Database error checking profile name: "+err.Error())
		return false // Return false on error to allow creation
	}
	defer rows.Close()

	// Check if any rows were returned
	exists := rows.Next()
	return exists // true if profile exists, false if it doesn't
}

func CheckProfileEmail(email string) bool {
	hashProfileEmail := utils.HashData(email)

	query := `
	SELECT hash_profile_email
	FROM ghostedjobs_profile
	WHERE hash_profile_email = $1
	`
	rows, err := db.Query(query, hashProfileEmail)
	if err != nil {
		logs.Logs(logErr, "Could not query database: "+err.Error())
		return false // Return false on error to allow creation
	}
	defer rows.Close()

	// Check if any rows were returned
	exists := rows.Next()
	return exists // true if email exists, false if it doesn't
}

func ValidateProfilePassword(profilePassword string) bool {
	hashProfilePassword := utils.HashData(profilePassword)

	query := `
	SELECT hash_profile_password
	FROM ghostedjobs_profile
	WHERE hash_profile_password = $1
	`
	rows, err := db.Query(query, hashProfilePassword)
	if err != nil {
		logs.Logs(logErr, "Could not query database: "+err.Error())
		return false // Return false on error
	}
	defer rows.Close()

	// Check if any rows were returned
	exists := rows.Next()
	return exists // true if password exists, false if it doesn't
}

func CreateNewProfile(profileName, profileEmail, profilePassword string) error {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is empty!")
		return errors.New("database connection not established")
	}

	// hash and encrypt profile data
	hashProfileName := utils.HashData(profileName)
	hashProfileEmail := utils.HashData(profileEmail)
	hashProfilePassword := utils.HashData(profilePassword)

	encryptProfileName, err := utils.Encrypt([]byte(profileName))
	if err != nil {
		logs.Logs(logErr, "Could not encrypt profile name: "+err.Error())
		return err
	}
	encryptProfileEmail, err := utils.Encrypt([]byte(profileEmail))
	if err != nil {
		logs.Logs(logErr, "Could not encrypt profile email: "+err.Error())
		return err
	}

	query := `
	INSERT INTO ghostedjobs_profile (
		hash_profile_name,
		hash_profile_email,
		hash_profile_password,
		encrypt_profile_name,
		encrypt_profile_email,
		created_at
	)
	VALUES ( $1, $2, $3, $4, $5, NOW() );
	`
	_, err = db.Exec(query, hashProfileName, hashProfileEmail, hashProfilePassword, encryptProfileName, encryptProfileEmail)
	if err != nil {
		logs.Logs(logDbErr, "Could not insert profile into database: "+err.Error())
		return err
	}

	return nil
}

func AuthenticateProfile(hashProfileName, hashProfileEmail, hashProfilePassword string) (bool, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return false, errors.New("database connection is not initialized")
	}

	var (
		dbHashProfileName     string
		dbHashProfileEmail    string
		dbHashProfilePassword string
	)
	query := `
	SELECT hash_profile_name, hash_profile_email, hash_profile_password
	FROM ghostedjobs_profile
	WHERE hash_profile_name = $1
		AND hash_profile_email = $2
		AND hash_profile_password = $3;
	`
	err := db.QueryRow(query, hashProfileName, hashProfileEmail, hashProfilePassword).Scan(&dbHashProfileName, &dbHashProfileEmail, &dbHashProfilePassword)
	if err != nil {
		logs.Logs(logDbErr, "Failed to authenticate profile: "+err.Error())
		return false, err
	}

	// verify user details
	verifyProfileName := utils.VerifyHash(hashProfileName, dbHashProfileName)
	if !verifyProfileName {
		logs.Logs(logDbErr, "Profile name does not match")
		return false, errors.New("profile name does not match")
	}
	verifyProfileEmail := utils.VerifyHash(hashProfileEmail, dbHashProfileEmail)
	if !verifyProfileEmail {
		logs.Logs(logDbErr, "Profile email does not match")
		return false, errors.New("profile email does not match")
	}
	verifyProfilePassword := utils.VerifyHash(hashProfilePassword, dbHashProfilePassword)
	if !verifyProfilePassword {
		logs.Logs(logDbErr, "Profile password does not match")
		return false, errors.New("profile password does not match")
	}

	return true, nil
}

func UpdateProfileSessionTokens(hashProfileEmail string) (string, string, time.Time, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return "", "", time.Time{}, errors.New("database connection is not initialized")
	}

	sessionToken, err := utils.GenerateToken(32)
	if err != nil {
		logs.Logs(logDbErr, "Failed to generate session token: "+err.Error())
		return "", "", time.Time{}, err
	}
	csrfToken, err := utils.GenerateToken(32)
	if err != nil {
		logs.Logs(logDbErr, "Failed to generate CSRF token: "+err.Error())
		return "", "", time.Time{}, err
	}
	expiry := time.Now().Add(5 * time.Minute) // 5 minutes validity

	query := `
	UPDATE ghostedjobs_profile 
	SET session_token=$1, csrf_token=$2, token_expiry=$3 
	WHERE hash_profile_email=$4;
	`
	result, err := db.Exec(query, sessionToken, csrfToken, expiry, hashProfileEmail)
	if err != nil {
		logs.Logs(logDbErr, "Failed to update session tokens: "+err.Error())
		return "", "", time.Time{}, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logs.Logs(logDbErr, "Failed to get rows affected: "+err.Error())
	} else if rowsAffected == 0 {
		logs.Logs(logDbErr, "No rows were updated for hash email: "+hashProfileEmail)
		return "", "", time.Time{}, errors.New("no profile found with the provided email")
	} else {
		logs.Logs(logDb, "Updated session tokens for "+fmt.Sprintf("%d", rowsAffected)+" rows")
	}

	logs.Logs(logDb, "Session tokens updated successfully")
	return sessionToken, csrfToken, expiry, nil
}

func GetHashEmailFromSessionToken(sessionToken string) (string, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return "", errors.New("database connection is not initialized")
	}

	var hashEmail string
	query := `
	SELECT hash_profile_email 
	FROM ghostedjobs_profile 
	WHERE session_token=$1;
	`
	err := db.QueryRow(query, sessionToken).Scan(&hashEmail)

	if err == sql.ErrNoRows {
		logs.Logs(logDbErr, "User not found")
		return "", errors.New("user not found")
	}

	if err != nil {
		logs.Logs(logDbErr, "Failed to get session token: "+err.Error())
		return "", err
	}

	logs.Logs(logDb, "Hash email retrieved successfully: "+hashEmail)

	return hashEmail, nil
}

func GetEncryptedProfileNameFromHashEmail(hashEmail string) (string, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return "", errors.New("database connection is not initialized")
	}

	var encryptedProfileName string
	query := `
	SELECT encrypt_profile_name
	FROM ghostedjobs_profile
	WHERE hash_profile_email=$1;
	`
	err := db.QueryRow(query, hashEmail).Scan(&encryptedProfileName)

	if err == sql.ErrNoRows {
		logs.Logs(logDbErr, "User not found")
		return "", errors.New("user not found")
	}

	if err != nil {
		logs.Logs(logDbErr, "Failed to get encrypted profile name: "+err.Error())
		return "", err
	}

	logs.Logs(logDb, "Encrypted profile name retrieved successfully")
	return encryptedProfileName, nil
}

func ValidateProfileSessionTokenFromHashEmail(hashEmail, sessionToken string) (bool, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return false, errors.New("database connection is not initialized")
	}

	// query DB to get the stored session token
	var dbSessionToken string
	query := `
	SELECT session_token
	FROM ghostedjobs_profile
	WHERE hash_profile_email = $1;
	`
	err := db.QueryRow(query, hashEmail).Scan(&dbSessionToken)

	if err == sql.ErrNoRows {
		logs.Logs(logDbErr, "User not found")
		return false, errors.New("user not found")
	}

	if err != nil {
		logs.Logs(logDbErr, "Failed to get session token: "+err.Error())
		return false, err
	}

	// compare the input session token with DB session token
	if sessionToken != dbSessionToken {
		logs.Logs(logDbErr, "Invalid session token. Expected: "+dbSessionToken+", Got: "+sessionToken)
		return false, nil
	}
	return true, nil
}

func ValidateProfileCSRFTokenFromHashEmail(hashEmail, csrfToken string) (bool, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return false, errors.New("database connection is not initialized")
	}

	// query DB to get the stored CSRF token
	var dbCSRFToken string
	query := `
	SELECT csrf_token 
	FROM ghostedjobs_profile 
	WHERE hash_profile_email=$1;
	`
	err := db.QueryRow(query, hashEmail).Scan(&dbCSRFToken)
	if err != nil {
		return false, err
	}

	// compare the input CSRF token with DB CSRF token
	if csrfToken != dbCSRFToken {
		return false, nil
	}
	return true, nil
}

func GetUserNameFromHashEmail(hashEmail string) (string, []byte, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return "", nil, errors.New("database connection is not initialized")
	}

	var (
		hashProfileName    string
		encryptProfileName []byte
	)
	query := `
	SELECT hash_profile_name, encrypt_profile_name
	FROM ghostedjobs_profile
	WHERE hash_profile_email = $1;
	`

	err := db.QueryRow(query, hashEmail).Scan(&hashProfileName, &encryptProfileName)
	if err != nil {
		logs.Logs(logDbErr, "Failed to get profile name: "+err.Error())
		return "", nil, err
	}

	return hashProfileName, encryptProfileName, nil
}

func CreateNewReview(
	hashProfileName string,
	encryptProfileName []byte,
	hashCompanyName string,
	encryptCompanyName []byte,
	interactionType string,
	encryptRecruiterName,
	encryptManagerName []byte,
	reviewRating string,
	encryptReviewContent []byte,
) error {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return errors.New("database connection is not initialized")
	}

	query := `
	INSERT INTO ghostedjobs_review (
		hash_profile_name,
		encrypt_profile_name,
		hash_company_name,
		encrypt_company_name,
		interaction_type,
		encrypt_recruiter_name,
		encrypt_manager_name,
		review_rating,
		encrypt_review_content,
		created_at
	)
	VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, NOW() );
	`

	_, err := db.Query(
		query,
		hashProfileName,
		encryptProfileName,
		hashCompanyName,
		encryptCompanyName,
		interactionType,
		encryptRecruiterName,
		encryptManagerName,
		reviewRating,
		encryptReviewContent,
	)
	if err != nil {
		logs.Logs(logDbErr, "Failed to create new GHOSTED! jobs review: "+err.Error())
		return err
	}

	return nil
}

func GetAllGhostedReviews() ([]GhostedReviews, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return nil, errors.New("database connection is not initialized")
	}

	query := `
	SELECT
		encrypt_company_name,
		interaction_type,
		encrypt_recruiter_name,
		encrypt_manager_name,
		review_rating,
		encrypt_review_content,
		created_at,
		encrypt_profile_name
	FROM ghostedjobs_review
	ORDER BY created_at DESC;
	`
	rows, err := db.Query(query)
	if err != nil {
		logs.Logs(logDbErr, "Failed to get all GHOSTED! jobs reviews: "+err.Error())
		return nil, err
	}
	defer rows.Close()

	var reviewsList []GhostedReviews
	for rows.Next() {
		var review GhostedReviews
		err := rows.Scan(
			&review.CompanyName,
			&review.InteractionType,
			&review.RecruiterName,
			&review.ManagerName,
			&review.ReviewRating,
			&review.ReviewContent,
			&review.CreatedAt,
			&review.ProfileName,
		)
		if err != nil {
			logs.Logs(logDbErr, "Failed to scan GHOSTED! jobs review: "+err.Error())
			return nil, err
		}
		reviewsList = append(reviewsList, review)
	}

	// check for errors from iterating over rows
	err = rows.Err()
	if err != nil {
		logs.Logs(logDbErr, "Failed to iterate over GHOSTED! jobs reviews: "+err.Error())
		return nil, err
	}

	return reviewsList, nil
}

//* SEARCH ENGINE FUNCTIONS

// TODO: get reviews by hash profile name
func GetAllReviewsByHashProfileName(hashProfileName string) ([]GhostedReviews, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return nil, errors.New("database connection is not initialized")
	}

	query := `
	SELECT
		encrypt_company_name,
		interaction_type,
		encrypt_recruiter_name,
		encrypt_manager_name,
		review_rating,
		encrypt_review_content,
		created_at,
		encrypt_profile_name
	FROM ghostedjobs_review
		WHERE hash_profile_name = $1
	ORDER BY created_at DESC; 
	`
	rows, err := db.Query(query, hashProfileName)
	if err != nil {
		logs.Logs(logDbErr, "Failed to get all GHOSTED! jobs reviews: "+err.Error())
		return nil, err
	}
	defer rows.Close()

	var reviewsList []GhostedReviews
	for rows.Next() {
		var review GhostedReviews
		err := rows.Scan(
			&review.CompanyName,
			&review.InteractionType,
			&review.RecruiterName,
			&review.ManagerName,
			&review.ReviewRating,
			&review.ReviewContent,
			&review.CreatedAt,
			&review.ProfileName,
		)
		if err != nil {
			logs.Logs(logDbErr, "Failed to scan GHOSTED! jobs review: "+err.Error())
			return nil, err
		}
		reviewsList = append(reviewsList, review)
	}

	// check for errors from iterating over rows
	err = rows.Err()
	if err != nil {
		logs.Logs(logDbErr, "Failed to iterate over GHOSTED! jobs reviews: "+err.Error())
		return nil, err
	}

	return reviewsList, nil
}

// TODO: get reviews by company name
func GetAllReviewsByCompanyName(companyName string) ([]GhostedReviews, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return nil, errors.New("database connection is not initialized")
	}

	query := `
	SELECT
		encrypt_company_name,
		interaction_type,
		encrypt_recruiter_name,
		encrypt_manager_name,
		review_rating,
		encrypt_review_content,
		created_at,
		encrypt_profile_name
	FROM ghostedjobs_review
		WHERE hash_company_name = $1
	ORDER BY created_at DESC;
	`
	rows, err := db.Query(query, utils.HashData(companyName))
	if err != nil {
		logs.Logs(logDbErr, fmt.Sprintf("Failed to get GHOSTED! job reviews for given company: %s, %s", companyName, err.Error()))
		return nil, err
	}
	defer rows.Close()

	var reviewsList []GhostedReviews
	for rows.Next() {
		var review GhostedReviews
		err := rows.Scan(
			&review.CompanyName,
			&review.InteractionType,
			&review.RecruiterName,
			&review.ManagerName,
			&review.ReviewRating,
			&review.ReviewContent,
			&review.CreatedAt,
			&review.ProfileName,
		)
		if err != nil {
			logs.Logs(logDbErr, "Failed to scan GHOSTED! jobs review: "+err.Error())
			return nil, err
		}
		reviewsList = append(reviewsList, review)
	}

	// check for errors from iterating over rows
	err = rows.Err()
	if err != nil {
		logs.Logs(logDbErr, "Failed to iterate over GHOSTED! jobs reviews: "+err.Error())
		return nil, err
	}

	// check if the company name exists in the database
	if len(reviewsList) == 0 {
		logs.Logs(logDbErr, "Company name does not exist in the database")
		return nil, errors.New("company name does not exist in the database")
	}

	return reviewsList, nil
}

// TODO: get reviews by interaction type
func GetAllReviewsByInteractionType(interactionType string) ([]GhostedReviews, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return nil, errors.New("database connection is not initialized")
	}

	query := `
	SELECT
		encrypt_company_name,
		interaction_type,
		encrypt_recruiter_name,
		encrypt_manager_name,
		review_rating,
		encrypt_review_content,
		created_at,
		encrypt_profile_name
	FROM ghostedjobs_review
		WHERE interaction_type = $1
	ORDER BY created_at DESC;
	`
	rows, err := db.Query(query, interactionType)
	if err != nil {
		logs.Logs(logDbErr, fmt.Sprintf("Failed to get GHOSTED! job reviews for given interaction type: %s, %s", interactionType, err.Error()))
		return nil, err
	}
	defer rows.Close()

	var reviewsList []GhostedReviews
	for rows.Next() {
		var review GhostedReviews
		err := rows.Scan(
			&review.CompanyName,
			&review.InteractionType,
			&review.RecruiterName,
			&review.ManagerName,
			&review.ReviewRating,
			&review.ReviewContent,
			&review.CreatedAt,
			&review.ProfileName,
		)
		if err != nil {
			logs.Logs(logDbErr, "Failed to scan GHOSTED! job review: "+err.Error())
			return nil, err
		}
		reviewsList = append(reviewsList, review)
	}

	// check for errors from iterating over rows
	err = rows.Err()
	if err != nil {
		logs.Logs(logDbErr, "Failed to iterate over GHOSTED! job reviews: "+err.Error())
		return nil, err
	}

	// check if the interaction type exists in the database
	if len(reviewsList) == 0 {
		logs.Logs(logDbErr, "No reviews found for this interaction type: "+interactionType)
		return nil, errors.New("no reviews found for this interaction type: " + interactionType)
	}

	return reviewsList, nil
}

// TODO: get reviews by review rating
func GetAllReviewsByReviewRating(reviewRating string) ([]GhostedReviews, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return nil, errors.New("database connection is not initialized")
	}

	query := `
	SELECT
		encrypt_company_name,
		interaction_type,
		encrypt_recruiter_name,
		encrypt_manager_name,
		review_rating,
		encrypt_review_content,
		created_at,
		encrypt_profile_name
	FROM ghostedjobs_review
		WHERE review_rating = $1
	ORDER BY created_at DESC;
	`
	rows, err := db.Query(query, reviewRating)
	if err != nil {
		logs.Logs(logDbErr, fmt.Sprintf("Failed to get GHOSTED! job reviews for given review rating: %s, %s", reviewRating, err.Error()))
		return nil, err
	}
	defer rows.Close()

	var reviewsList []GhostedReviews
	for rows.Next() {
		var review GhostedReviews
		err := rows.Scan(
			&review.CompanyName,
			&review.InteractionType,
			&review.RecruiterName,
			&review.ManagerName,
			&review.ReviewRating,
			&review.ReviewContent,
			&review.CreatedAt,
			&review.ProfileName,
		)
		if err != nil {
			logs.Logs(logDbErr, "Failed to scan GHOSTED! job review: "+err.Error())
			return nil, err
		}
		reviewsList = append(reviewsList, review)
	}

	// check for errors from iterating over rows
	err = rows.Err()
	if err != nil {
		logs.Logs(logDbErr, "Failed to iterate over GHOSTED! job reviews: "+err.Error())
		return nil, err
	}

	// check if the review rating exists in the database
	if len(reviewsList) == 0 {
		logs.Logs(logDbErr, "No reviews found for this review rating: "+reviewRating)
		return nil, errors.New("no reviews found for this review rating: " + reviewRating)
	}

	return reviewsList, nil
}

func Logout(hashEmail string) error {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return errors.New("database connection is not initialized")
	}

	query := `
	UPDATE ghostedjobs_profile
		SET session_token = NULL,
			csrf_token = NULL,
			token_expiry = NULL
	WHERE hash_profile_email = $1;
	`
	_, err := db.Exec(query, hashEmail)
	if err != nil {
		logs.Logs(logDbErr, "Failed to logout profile: "+err.Error())
		return err
	}

	return nil
}
