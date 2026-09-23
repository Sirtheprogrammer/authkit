package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"authkit/internal/crypto"
)

// RunInit guides the user through an interactive setup wizard to generate .env and authkit.yaml
func RunInit() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=====================================================")
	fmt.Println("             AuthKit Setup Wizard                    ")
	fmt.Println("   Stateless Authentication & User Management Kit   ")
	fmt.Println("=====================================================")
	fmt.Println()

	// 1. Port
	fmt.Print("1. Server Port [default: 8080]: ")
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	port := 8080
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	// 2. Base URL
	fmt.Print("2. Base URL [default: http://localhost:8080]: ")
	baseURL, _ := reader.ReadString('\n')
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d", port)
	}

	// 3. Database Selection
	fmt.Println("\n3. Choose Database Engine:")
	fmt.Println("   [1] SQLite (Zero-config embedded, recommended for local/quickstart)")
	fmt.Println("   [2] PostgreSQL")
	fmt.Println("   [3] MySQL")
	fmt.Println("   [4] MongoDB")
	fmt.Print("   Select (1-4) [default: 1]: ")
	dbChoice, _ := reader.ReadString('\n')
	dbChoice = strings.TrimSpace(dbChoice)

	dbType := "sqlite"
	dbURL := ""
	dbFile := "./authkit.db"

	switch dbChoice {
	case "2":
		dbType = "postgres"
		fmt.Print("   Enter PostgreSQL URL [e.g. postgres://user:pass@localhost:5432/authkit?sslmode=disable]: ")
		dbURL, _ = reader.ReadString('\n')
		dbURL = strings.TrimSpace(dbURL)
	case "3":
		dbType = "mysql"
		fmt.Print("   Enter MySQL URL [e.g. root:pass@tcp(localhost:3306)/authkit?parseTime=true]: ")
		dbURL, _ = reader.ReadString('\n')
		dbURL = strings.TrimSpace(dbURL)
	case "4":
		dbType = "mongodb"
		fmt.Print("   Enter MongoDB URL [e.g. mongodb://localhost:27017/authkit]: ")
		dbURL, _ = reader.ReadString('\n')
		dbURL = strings.TrimSpace(dbURL)
	default:
		dbType = "sqlite"
		fmt.Print("   Enter SQLite file path [default: ./authkit.db]: ")
		inputPath, _ := reader.ReadString('\n')
		inputPath = strings.TrimSpace(inputPath)
		if inputPath != "" {
			dbFile = inputPath
		}
	}

	// 4. JWT Signing Algorithm
	fmt.Println("\n4. JWT Signing Algorithm:")
	fmt.Println("   [1] RS256 (Asymmetric RSA key pair with JWKS, recommended for microservices)")
	fmt.Println("   [2] HS256 (Symmetric HMAC Secret)")
	fmt.Print("   Select (1-2) [default: 1]: ")
	jwtChoice, _ := reader.ReadString('\n')
	jwtChoice = strings.TrimSpace(jwtChoice)

	jwtAlgo := "RS256"
	hmacSecret := ""
	if jwtChoice == "2" {
		jwtAlgo = "HS256"
		secret, _ := crypto.GenerateRandomHex(32)
		hmacSecret = secret
	}

	// 5. Email Provider
	fmt.Println("\n5. Email Notification Provider:")
	fmt.Println("   [1] Mock / Local Console (Prints verification emails to log, zero-config)")
	fmt.Println("   [2] SMTP (Bring your own SMTP server)")
	fmt.Println("   [3] Resend SDK (Resend.com API Key)")
	fmt.Print("   Select (1-3) [default: 1]: ")
	emailChoice, _ := reader.ReadString('\n')
	emailChoice = strings.TrimSpace(emailChoice)

	emailProvider := "mock"
	smtpHost := ""
	smtpUser := ""
	smtpPass := ""
	resendKey := ""

	if emailChoice == "2" {
		emailProvider = "smtp"
		fmt.Print("   SMTP Host [e.g. smtp.gmail.com]: ")
		smtpHost, _ = reader.ReadString('\n')
		smtpHost = strings.TrimSpace(smtpHost)
		fmt.Print("   SMTP Username: ")
		smtpUser, _ = reader.ReadString('\n')
		smtpUser = strings.TrimSpace(smtpUser)
		fmt.Print("   SMTP Password: ")
		smtpPass, _ = reader.ReadString('\n')
		smtpPass = strings.TrimSpace(smtpPass)
	} else if emailChoice == "3" {
		emailProvider = "resend"
		fmt.Print("   Resend API Key [e.g. re_...]: ")
		resendKey, _ = reader.ReadString('\n')
		resendKey = strings.TrimSpace(resendKey)
	}

	// Write .env file
	var envContent strings.Builder
	envContent.WriteString(fmt.Sprintf("PORT=%d\n", port))
	envContent.WriteString(fmt.Sprintf("BASE_URL=%s\n", baseURL))
	envContent.WriteString(fmt.Sprintf("DB_TYPE=%s\n", dbType))
	if dbType == "sqlite" {
		envContent.WriteString(fmt.Sprintf("DB_FILE=%s\n", dbFile))
	} else {
		envContent.WriteString(fmt.Sprintf("DATABASE_URL=%s\n", dbURL))
	}
	envContent.WriteString(fmt.Sprintf("JWT_ALGORITHM=%s\n", jwtAlgo))
	if hmacSecret != "" {
		envContent.WriteString(fmt.Sprintf("JWT_SECRET=%s\n", hmacSecret))
	}
	envContent.WriteString(fmt.Sprintf("EMAIL_PROVIDER=%s\n", emailProvider))
	if emailProvider == "smtp" {
		envContent.WriteString(fmt.Sprintf("SMTP_HOST=%s\n", smtpHost))
		envContent.WriteString(fmt.Sprintf("SMTP_PORT=587\n"))
		envContent.WriteString(fmt.Sprintf("SMTP_USERNAME=%s\n", smtpUser))
		envContent.WriteString(fmt.Sprintf("SMTP_PASSWORD=%s\n", smtpPass))
	} else if emailProvider == "resend" {
		envContent.WriteString(fmt.Sprintf("RESEND_API_KEY=%s\n", resendKey))
	}
	envContent.WriteString("MCP_ENABLED=true\n")

	if err := os.WriteFile(".env", []byte(envContent.String()), 0644); err != nil {
		return fmt.Errorf("failed to write .env file: %w", err)
	}

	// Write authkit.yaml configuration template
	yamlContent := fmt.Sprintf(`server:
  port: %d
  host: "0.0.0.0"
  base_url: "%s"
  environment: "development"
  allowed_origins: ["*"]

database:
  type: "%s"
  filepath: "%s"
  url: "%s"

jwt:
  algorithm: "%s"
  issuer: "authkit"
  access_expiry: 15m
  refresh_expiry: 168h
  require_email_verification: false

schema:
  strict: false
  fields:
    - name: name
      type: string
      required: false
      max_length: 100
    - name: company
      type: string
      required: false
    - name: tier
      type: string
      allowed_values: ["free", "pro", "enterprise"]
      default: "free"

oauth:
  google:
    enabled: false
    client_id: ""
    client_secret: ""
    redirect_url: "%s/api/v1/auth/oauth/google/callback"
  firebase:
    enabled: false
    project_id: ""
  github:
    enabled: false
    client_id: ""
    client_secret: ""
    redirect_url: "%s/api/v1/auth/oauth/github/callback"

email:
  provider: "%s"
  from_email: "auth@authkit.local"
  from_name: "AuthKit"

mcp:
  enabled: true
`, port, baseURL, dbType, dbFile, dbURL, jwtAlgo, baseURL, baseURL, emailProvider)

	if err := os.WriteFile("authkit.yaml", []byte(yamlContent), 0644); err != nil {
		return fmt.Errorf("failed to write authkit.yaml: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Generated .env successfully.")
	fmt.Println("✓ Generated authkit.yaml successfully.")
	fmt.Println()
	fmt.Println("Setup complete! You can now start AuthKit with:")
	fmt.Println("   ./authkit serve")
	fmt.Println()
	return nil
}
