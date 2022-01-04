package env

import "gitlab.com/piccolo_su/vegeta/pkg/util"

var (
	EmailEnabled        = "EMAIL_ENABLED"
	DefaultEmailEnabled = "false"

	EmailUsername        = "EMAIL_USERNAME"
	DefaultEmailUsername = "username"

	EmailHost        = "EMAIL_HOST"
	DefaultEmailHost = "smtp.feishu.com"

	EmailPort        = "EMAIL_PORT"
	DefaultEmailPort = "465"

	EmailPassword = "EMAIL_PASSWORD"

	EmailSuffix        = "EMAIL_SUFFIX"
	DefaultEmailSuffix = "*"

	EmailOfficialName        = "EMAIL_OFFICIAL_NAME"
	DefaultEmailOfficialName = "Navigator"

	ContactEmail        = "EMAIL_CONTACT_NAME"
	DefaultContactEmail = "info@tensorsecurity.cn"
)

func GetEmailCheck() bool {
	return util.GetEnvWithDefault(EmailEnabled, DefaultEmailEnabled) == "true"
}

func GetEmailUsername() string {
	return util.GetEnvWithDefault(EmailUsername, DefaultEmailUsername)
}

func GetEmailHost() string {
	return util.GetEnvWithDefault(EmailHost, DefaultEmailHost)
}

func GetEmailPort() string {
	return util.GetEnvWithDefault(EmailPort, DefaultEmailPort)
}

func GetEmailPassword() string {
	return util.GetEnvWithDefault(EmailPassword, "")
}

func GetContactEmail() string {
	return util.GetEnvWithDefault(ContactEmail, DefaultContactEmail)
}

func GetEmailOfficialName() string {
	return util.GetEnvWithDefault(EmailOfficialName, DefaultEmailOfficialName)
}

func GetEmailSuffix() string {
	return util.GetEnvWithDefault(EmailSuffix, DefaultEmailSuffix)
}
