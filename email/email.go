package email

import (
	"fmt"
	"net/smtp"
	"os"

	"github.com/Bevs-n-Devs/ghostedjobs/env"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
)

func NewProfileNotificationEmail(userEmail, profileName, profilePassword string) error {
	if os.Getenv("GHOSTEDJOBS_EMAIL") == "" || os.Getenv("GHOSTEDJOBS_PASSWORD") == "" {
		logs.Logs(logWarn, "Could not get email credentials from hosting platform. Loading from .env file...")
		err := env.LoadEnv("env/.env")
		if err != nil {
			logs.Logs(logErr, fmt.Sprintf("Unable to load environment variables: %s", err.Error()))
		}
	}

	// Update smptUser, smptPassword, recipient, and ccEmail variables
	smptUser = os.Getenv("GHOSTEDJOBS_EMAIL")
	smptPassword = os.Getenv("GHOSTEDJOBS_PASSWORD")
	recipient = userEmail
	ccEmail = os.Getenv("GHOSTEDJOBS_BACKUP_EMAIL")

	if smptUser == "" || smptPassword == "" || recipient == "" {
		logs.Logs(logErr, "Email credentials are empty!")
		return fmt.Errorf("email credentials are empty")
	}

	if recipient == ccEmail {
		logs.Logs(logWarn, "Primary and secondary email addresses are the same, skipping CC")
		ccEmail = ""
	}

	subject := "New Profile Created"
	body := fmt.Sprintf(`
You have created a new profile for Ghosted Jobs.

Your profile details are as follows:

	Profile Name: %s
	Profile Email: %s
	Profile Password: %s

Please keep this information safe and secure.
If you did not create this profile, please contact us immediately.

You can login to your profile at https://ghostedjobs.net/#summonYourSpirit

Yours sincerely,

The Ghosted Jobs Team
https://ghostedjobs.net

Ghosted Jobs is a platform that allows you to anonymously review companies and their hiring processes. 
We are committed to providing a safe and secure environment for our users. 
If you have any questions or concerns, please do not hesitate to contact us.
	`, profileName, userEmail, profilePassword)

	auth := smtp.PlainAuth("", smptUser, smptPassword, smptHost)
	err := smtp.SendMail(smptHost+":"+smptPort, auth, smptUser, []string{recipient, ccEmail}, []byte("Subject: "+subject+"\n\n"+body))
	if err != nil {
		logs.Logs(logErr, fmt.Sprintf("Failed to send email: %s", err.Error()))
		return err
	}

	logs.Logs(logInfo, "Email sent successfully. User notified of new profile creation.")
	return nil
}
