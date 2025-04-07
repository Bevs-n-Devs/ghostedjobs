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

func UpdateProfileSessionTokens(email string) (string, string, time.Time, error) {
	if db == nil {
		logs.Logs(logDbErr, "Database connection is not initialized")
		return "", "", time.Time{}, errors.New("database connection is not initialized")
	}

	hashProfileEmail := utils.HashData(email)

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
	expiry := time.Now().Add(30 * time.Second) // 30 seconds validity

	query := `
	UPDATE ghostedjobs_profile 
	SET session_token=$1, csrf_token=$2, token_expiry=$3 
	WHERE hash_profile_email=$4;
	`
	_, err = db.Exec(query, sessionToken, csrfToken, expiry, hashProfileEmail)
	if err != nil {
		logs.Logs(logDbErr, "Failed to update session tokens: "+err.Error())
		return "", "", time.Time{}, err
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

	return hashEmail, nil
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
		logs.Logs(logDbErr, "Invalid session token")
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
