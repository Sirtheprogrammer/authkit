package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"authkit/internal/cli"
	"authkit/internal/config"
	"authkit/internal/db/factory"
	"authkit/internal/jwt"
	"authkit/internal/mcp"
	"authkit/internal/service"
)

const Version = "1.0.0"

func main() {
	configPath := flag.String("config", "authkit.yaml", "Path to authkit.yaml configuration file")
	flag.Parse()

	args := flag.Args()
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Printf("[WARN] Error loading config: %v (using defaults)", err)
		cfg = config.DefaultConfig()
	}

	switch command {
	case "init":
		if err := cli.RunInit(); err != nil {
			log.Fatalf("Init failed: %v", err)
		}

	case "serve":
		if err := cli.RunServe(cfg); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}

	case "migrate":
		log.Printf("Running migrations for %s...", cfg.Database.Type)
		ctx := context.Background()
		db, err := factory.NewDatabase(ctx, cfg.Database)
		if err != nil {
			log.Fatalf("Migration failed: %v", err)
		}
		defer db.Close()
		log.Println("✓ Migrations completed successfully.")

	case "admin":
		if len(args) < 2 || args[1] != "create" {
			fmt.Println("Usage: authkit admin create <email> <password>")
			os.Exit(1)
		}
		if len(args) < 4 {
			fmt.Println("Error: email and password are required")
			fmt.Println("Usage: authkit admin create <email> <password>")
			os.Exit(1)
		}
		if err := cli.CreateSuperAdmin(cfg, args[2], args[3]); err != nil {
			log.Fatalf("Failed to create admin: %v", err)
		}

	case "token":
		if len(args) < 2 || args[1] != "generate" {
			fmt.Println("Usage: authkit token generate [user_id] [email] [role]")
			os.Exit(1)
		}
		uid := ""
		email := ""
		role := ""
		if len(args) > 2 {
			uid = args[2]
		}
		if len(args) > 3 {
			email = args[3]
		}
		if len(args) > 4 {
			role = args[4]
		}
		if err := cli.GenerateTestToken(cfg, uid, email, role); err != nil {
			log.Fatalf("Failed to generate token: %v", err)
		}

	case "mcp":
		ctx := context.Background()
		database, err := factory.NewDatabase(ctx, cfg.Database)
		if err != nil {
			log.Fatalf("MCP database connection failed: %v", err)
		}
		defer database.Close()

		tm, err := jwt.NewTokenManager(jwt.Config{
			Issuer:           cfg.JWT.Issuer,
			AccessExpiry:     cfg.JWT.AccessExpiry,
			RefreshExpiry:    cfg.JWT.RefreshExpiry,
			SigningAlgorithm: cfg.JWT.Algorithm,
			RSAPrivateKeyPEM: cfg.JWT.PrivateKeyPEM,
			RSAPublicKeyPEM:  cfg.JWT.PublicKeyPEM,
			HMACSecret:       cfg.JWT.HMACSecret,
			KeyID:            cfg.JWT.KeyID,
		})
		if err != nil {
			log.Fatalf("MCP token manager failed: %v", err)
		}

		schemaService := service.NewSchemaService(cfg.Schema)
		userService := service.NewUserService(database, schemaService)
		authService := service.NewAuthService(cfg, database, tm, schemaService, nil)
		mcpHandler := mcp.NewHandler(userService, authService, tm, database, cfg)
		mcpServer := mcp.NewServer(mcpHandler)

		if err := mcpServer.RunStdio(ctx); err != nil {
			log.Fatalf("MCP stdio server terminated: %v", err)
		}

	case "version", "-v", "--version":
		fmt.Printf("AuthKit version %s\n", Version)

	case "help", "-h", "--help":
		printHelp()

	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf("AuthKit v%s - Stateless Authentication & User Management Kit\n\n", Version)
	fmt.Println("Usage:")
	fmt.Println("  authkit [command] [flags]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  serve              Start the AuthKit HTTP service and web UI (default)")
	fmt.Println("  init               Interactive setup wizard to configure .env and authkit.yaml")
	fmt.Println("  migrate            Run schema migrations on the configured database")
	fmt.Println("  admin create       Provision a superadmin user account (email password)")
	fmt.Println("  token generate     Generate a test stateless JWT token")
	fmt.Println("  mcp                Run the Model Context Protocol (MCP) server over stdio")
	fmt.Println("  version            Show version information")
	fmt.Println("  help               Show help instructions")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  --config <path>    Path to YAML configuration file (default: authkit.yaml)")
}
