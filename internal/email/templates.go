package email

import (
	"bytes"
	"fmt"
	"html/template"
)

// EmailData holds variables for rendering templates
type EmailData struct {
	AppName     string
	UserName    string
	Code        string
	ActionURL   string
	SupportURL  string
	Year        int
	ExpiryMins  int
}

const baseEmailStyle = `
  body {
    margin: 0;
    padding: 0;
    background-color: #09090b;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    color: #e4e4e7;
  }
  .container {
    max-width: 560px;
    margin: 40px auto;
    background: #18181b;
    border: 1px solid #27272a;
    border-radius: 12px;
    overflow: hidden;
    padding: 36px 32px;
  }
  .brand {
    font-size: 20px;
    font-weight: 700;
    letter-spacing: -0.5px;
    color: #ffffff;
    margin-bottom: 24px;
    display: inline-block;
  }
  h1 {
    font-size: 22px;
    font-weight: 600;
    color: #ffffff;
    margin: 0 0 16px 0;
    letter-spacing: -0.4px;
  }
  p {
    font-size: 14px;
    line-height: 1.6;
    color: #a1a1aa;
    margin: 0 0 20px 0;
  }
  .code-box {
    background: #09090b;
    border: 1px solid #3f3f46;
    border-radius: 8px;
    padding: 18px 24px;
    text-align: center;
    margin: 28px 0;
  }
  .code-text {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 32px;
    font-weight: 700;
    letter-spacing: 8px;
    color: #ffffff;
  }
  .btn-container {
    margin: 28px 0;
    text-align: center;
  }
  .btn {
    display: inline-block;
    background-color: #ffffff;
    color: #09090b !important;
    font-weight: 600;
    font-size: 14px;
    padding: 12px 28px;
    border-radius: 6px;
    text-decoration: none;
  }
  .footer {
    margin-top: 32px;
    padding-top: 20px;
    border-top: 1px solid #27272a;
    font-size: 12px;
    color: #71717a;
  }
`

const verificationHTMLTmpl = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verify your email</title>
<style>` + baseEmailStyle + `</style>
</head>
<body>
  <div class="container">
    <div class="brand">{{.AppName}}</div>
    <h1>Verify your email address</h1>
    <p>Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},</p>
    <p>Thank you for signing up. Please use the 6-digit verification code below or click the button to verify your email address.</p>
    
    {{if .Code}}
    <div class="code-box">
      <div class="code-text">{{.Code}}</div>
    </div>
    {{end}}

    {{if .ActionURL}}
    <div class="btn-container">
      <a href="{{.ActionURL}}" class="btn" target="_blank">Verify Email</a>
    </div>
    <p style="font-size: 12px; color: #71717a; word-break: break-all;">Or paste this link into your browser: <br>{{.ActionURL}}</p>
    {{end}}

    <p>This code will expire in {{.ExpiryMins}} minutes. If you did not create an account, you can safely ignore this email.</p>

    <div class="footer">
      &copy; {{.Year}} {{.AppName}}. All rights reserved.
    </div>
  </div>
</body>
</html>`

const passwordResetHTMLTmpl = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reset your password</title>
<style>` + baseEmailStyle + `</style>
</head>
<body>
  <div class="container">
    <div class="brand">{{.AppName}}</div>
    <h1>Reset your password</h1>
    <p>Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},</p>
    <p>We received a request to reset your password. Use the verification code below or click the button to set a new password.</p>

    {{if .Code}}
    <div class="code-box">
      <div class="code-text">{{.Code}}</div>
    </div>
    {{end}}

    {{if .ActionURL}}
    <div class="btn-container">
      <a href="{{.ActionURL}}" class="btn" target="_blank">Reset Password</a>
    </div>
    <p style="font-size: 12px; color: #71717a; word-break: break-all;">Or paste this link into your browser: <br>{{.ActionURL}}</p>
    {{end}}

    <p>This link and code will expire in {{.ExpiryMins}} minutes. If you did not request a password reset, please secure your account immediately.</p>

    <div class="footer">
      &copy; {{.Year}} {{.AppName}}. All rights reserved.
    </div>
  </div>
</body>
</html>`

const welcomeHTMLTmpl = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Welcome to {{.AppName}}</title>
<style>` + baseEmailStyle + `</style>
</head>
<body>
  <div class="container">
    <div class="brand">{{.AppName}}</div>
    <h1>Welcome to {{.AppName}}</h1>
    <p>Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},</p>
    <p>Your account is ready. You now have full access to your authentication and user management services.</p>

    {{if .ActionURL}}
    <div class="btn-container">
      <a href="{{.ActionURL}}" class="btn" target="_blank">Go to Dashboard</a>
    </div>
    {{end}}

    <div class="footer">
      &copy; {{.Year}} {{.AppName}}. All rights reserved.
    </div>
  </div>
</body>
</html>`

// RenderVerificationEmail renders verification email HTML and text
func RenderVerificationEmail(data EmailData) (html string, text string, err error) {
	if data.ExpiryMins <= 0 {
		data.ExpiryMins = 30
	}
	tmpl, err := template.New("verify").Parse(verificationHTMLTmpl)
	if err != nil {
		return "", "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", "", err
	}
	plain := fmt.Sprintf("Verify your email for %s\n\nYour code is: %s\n\nOr visit: %s\n(Expires in %d minutes)",
		data.AppName, data.Code, data.ActionURL, data.ExpiryMins)
	return buf.String(), plain, nil
}

// RenderPasswordResetEmail renders password reset email HTML and text
func RenderPasswordResetEmail(data EmailData) (html string, text string, err error) {
	if data.ExpiryMins <= 0 {
		data.ExpiryMins = 30
	}
	tmpl, err := template.New("reset").Parse(passwordResetHTMLTmpl)
	if err != nil {
		return "", "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", "", err
	}
	plain := fmt.Sprintf("Reset your password for %s\n\nYour code is: %s\n\nOr visit: %s\n(Expires in %d minutes)",
		data.AppName, data.Code, data.ActionURL, data.ExpiryMins)
	return buf.String(), plain, nil
}

// RenderWelcomeEmail renders welcome email HTML and text
func RenderWelcomeEmail(data EmailData) (html string, text string, err error) {
	tmpl, err := template.New("welcome").Parse(welcomeHTMLTmpl)
	if err != nil {
		return "", "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", "", err
	}
	plain := fmt.Sprintf("Welcome to %s!\n\nYour account is active and ready to use.\nVisit: %s",
		data.AppName, data.ActionURL)
	return buf.String(), plain, nil
}
