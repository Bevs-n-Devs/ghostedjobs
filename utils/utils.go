package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"golang.org/x/crypto/bcrypt"
)

/*
HashedPassword generates a hashed password with a cost of 2^10.

It takes a string representation of a password and returns a byte slice
representing the hashed password. The second return value is an error type
that is non-nil if an error occurs while hashing the password.

Arguments:

- password: A string representation of the password to hash.

Returns:

- string: A string representation of the hashed password.

- error: An error type that is non-nil if an error occurs while hashing the password.
*/
func HashedPassword(password string) (string, error) {
	// byte representation of the password string, password hashed 2^10 times
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

/*
Checks a hashed password against a given password.
Returns true if the given password matches the hashed password, false if not.

Arguments:

- password: A string representation of the password to check.

- hash: A string representation of the hashed password to check against.

Returns:

- bool: True if the given password matches the hashed password, false if not.
*/
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

/*
HashData takes a string and returns a SHA-256 hash of the string.

The resulting hash is a fixed-size 256-bit string, represented as
a 64-character hexadecimal string.
*/
func HashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

/*
VerifyHash takes an input string and a stored hash string and
returns true if the two hashes match, or false if they do not.

This is a simple equality check and does not provide any
additional security features. It is the responsibility of the
caller to ensure that the input string and stored hash are valid
and have been secured appropriately.
*/
func VerifyHash(input string, storedHash string) bool {
	return input == storedHash // Compare with the stored hash
}

/*
Encrypts any identifiable data the user enters.
Will need the MASTER_KEY from envrionment variable to work.

We need to convert the data into bytes to encrypt it.

Return a list of bytes or an error.
*/
func Encrypt(data []byte) ([]byte, error) {
	// create a new AES cipher block using the master key
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		logs.Logs(logErr, fmt.Sprintf("Error creating AES cipher block: %s", err.Error()))
		return nil, err // Return error if key is invalid
	}

	// Create a GCM (Galois Counter Mode) cipher from the AES block
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		logs.Logs(logErr, fmt.Sprintf("Error creating GCM cipher: %s", err.Error()))
		return nil, err // Return error if GCM initialization fails
	}

	// Generate a nonce (unique number used only once) of required size
	nonce := make([]byte, gcm.NonceSize())   // GCM nonce should be unique per encryption
	_, err = io.ReadFull(rand.Reader, nonce) // Fill nonce with random bytes
	if err != nil {
		logs.Logs(logErr, fmt.Sprintf("Error generating nonce: %s", err.Error()))
		return nil, err // Return error if random generation fails
	}

	// Encrypt the data using AES-GCM
	// Seal appends encrypted data to nonce (authentication tag included)
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Return the concatenated nonce + ciphertext
	logs.Logs(logInfo, "Data encrypted successfully")
	return append(nonce, ciphertext...), nil
}

/*
Decrypt decrypts the given encrypted data using AES-GCM with the master key.
It expects the data to contain the nonce followed by the ciphertext.

Parameters:

	data ([]byte): The encrypted data containing the nonce and ciphertext.

Returns:

	([]byte): The decrypted plaintext if successful.
	(error): An error if the decryption process fails, such as an invalid key or corrupted data.
*/
func Decrypt(data []byte) ([]byte, error) {
	// Create a new AES cipher block using the same master key
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		logs.Logs(logErr, fmt.Sprintf("Error creating AES cipher block: %s", err.Error()))
		return nil, err // Return error if key is invalid
	}

	// Create a GCM cipher from the AES block
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		logs.Logs(logErr, fmt.Sprintf("Error creating GCM cipher: %s", err.Error()))
		return nil, err // Return error if GCM initialization fails
	}

	// Extract the nonce from the start of the encrypted data
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt the ciphertext using AES-GCM
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		logs.Logs(logErr, fmt.Sprintf("Error decrypting data: %s", err.Error()))
		return nil, err // Return error if decryption fails
	}

	// Return the decrypted plaintext
	logs.Logs(logInfo, "Data decrypted successfully")
	return plaintext, nil
}

/*
GenerateToken generates a cryptographically secure random token of a given length.
It takes a single int argument, the length of the token to generate.
It returns a string representation of the generated token and an error. The
error is non-nil if an error occurs while generating the token.

Arguments:

- length: An int representing the length of the token to generate.

Returns:

- string: A string representation of the generated token.

- error: An error type that is non-nil if an error occurs while generating the token.
*/
func GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		logs.Logs(logErr, fmt.Sprintf("Error generating token: %s", err.Error()))
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

/*
Checks if a given password matches a confirmation password.
Returns true if the passwords match, false if not.

Arguments:

- password: A string representation of the password to check.

- confirmPassword: A string representation of the confirmation password to check against.

Returns:

- bool: True if the passwords match, false if not.
*/
func ValidateNewPassword(password, confirmPassword string) bool {
	return password == confirmPassword
}
