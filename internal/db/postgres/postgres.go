package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"authkit/internal/config"
	"authkit/internal/db"
	"authkit/internal/domain"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

// PostgresDB implements db.Database for PostgreSQL
type PostgresDB struct {
	cfg config.DatabaseConfig
	db  *sql.DB
}

// New creates a new PostgreSQL database adapter
func New(cfg config.DatabaseConfig) *PostgresDB {
	return &PostgresDB{cfg: cfg}
}

func (p *PostgresDB) Type() string {
	return "postgres"
}

func (p *PostgresDB) Connect(ctx context.Context) error {
	dsn := p.cfg.URL
	if dsn == "" {
		host := p.cfg.Host
		if host == "" {
			host = "localhost"
		}
		port := p.cfg.Port
		if port <= 0 {
			port = 5432
		}
		user := p.cfg.User
		if user == "" {
			user = "postgres"
		}
		sslmode := p.cfg.SSLMode
		if sslmode == "" {
			sslmode = "disable"
		}
		dbname := p.cfg.Database
		if dbname == "" {
			dbname = "authkit"
		}
		dsn = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			host, port, user, p.cfg.Password, dbname, sslmode)
	}

	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to open postgres database: %w", err)
	}

	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(5 * time.Minute)

	if err := conn.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping postgres database: %w", err)
	}

	p.db = conn
	return nil
}

func (p *PostgresDB) Ping(ctx context.Context) error {
	if p.db == nil {
		return fmt.Errorf("postgres database is not connected")
	}
	return p.db.PingContext(ctx)
}

func (p *PostgresDB) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (p *PostgresDB) Migrate(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(64) PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255),
			role VARCHAR(32) NOT NULL DEFAULT 'user',
			status VARCHAR(32) NOT NULL DEFAULT 'active',
			email_verified BOOLEAN NOT NULL DEFAULT FALSE,
			metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			last_login_at TIMESTAMPTZ
		);`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
		`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);`,
		`CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);`,

		`CREATE TABLE IF NOT EXISTS sessions (
			id VARCHAR(64) PRIMARY KEY,
			user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			refresh_token_hash VARCHAR(128) UNIQUE NOT NULL,
			user_agent TEXT,
			client_ip VARCHAR(64),
			is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(refresh_token_hash);`,

		`CREATE TABLE IF NOT EXISTS verification_tokens (
			id VARCHAR(64) PRIMARY KEY,
			user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			email VARCHAR(255) NOT NULL,
			token_hash VARCHAR(128) NOT NULL,
			code VARCHAR(32),
			type VARCHAR(32) NOT NULL,
			used BOOLEAN NOT NULL DEFAULT FALSE,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_vt_token_hash ON verification_tokens(token_hash);`,
		`CREATE INDEX IF NOT EXISTS idx_vt_email_code ON verification_tokens(email, code);`,

		`CREATE TABLE IF NOT EXISTS oauth_accounts (
			id VARCHAR(64) PRIMARY KEY,
			user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			provider VARCHAR(32) NOT NULL,
			provider_user_id VARCHAR(255) NOT NULL,
			email VARCHAR(255) NOT NULL,
			avatar_url TEXT,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			UNIQUE(provider, provider_user_id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_user_id ON oauth_accounts(user_id);`,

		`CREATE TABLE IF NOT EXISTS audit_logs (
			id VARCHAR(64) PRIMARY KEY,
			user_id VARCHAR(64),
			action VARCHAR(64) NOT NULL,
			ip_address VARCHAR(64),
			user_agent TEXT,
			metadata TEXT,
			created_at TIMESTAMPTZ NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);`,
	}

	for _, q := range queries {
		if _, err := p.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("postgres migration failed on query: %w", err)
		}
	}

	return nil
}

// User CRUD
func (p *PostgresDB) CreateUser(ctx context.Context, u *domain.User) error {
	metaJSON, err := u.MetadataJSON()
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `INSERT INTO users (id, email, password_hash, role, status, email_verified, metadata, created_at, updated_at, last_login_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err = p.db.ExecContext(ctx, query,
		u.ID, u.Email, u.PasswordHash, string(u.Role), string(u.Status),
		u.EmailVerified, string(metaJSON), u.CreatedAt, u.UpdatedAt, u.LastLoginAt)

	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return db.ErrDuplicateEmail
		}
		return err
	}
	return nil
}

func (p *PostgresDB) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	query := `SELECT id, email, password_hash, role, status, email_verified, metadata, created_at, updated_at, last_login_at
		FROM users WHERE id = $1 LIMIT 1`

	return p.scanUser(p.db.QueryRowContext(ctx, query, id))
}

func (p *PostgresDB) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `SELECT id, email, password_hash, role, status, email_verified, metadata, created_at, updated_at, last_login_at
		FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`

	return p.scanUser(p.db.QueryRowContext(ctx, query, email))
}

func (p *PostgresDB) UpdateUser(ctx context.Context, u *domain.User) error {
	metaJSON, err := u.MetadataJSON()
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `UPDATE users SET
		email = $1, password_hash = $2, role = $3, status = $4,
		email_verified = $5, metadata = $6, updated_at = $7, last_login_at = $8
		WHERE id = $9`

	res, err := p.db.ExecContext(ctx, query,
		u.Email, u.PasswordHash, string(u.Role), string(u.Status),
		u.EmailVerified, string(metaJSON), u.UpdatedAt, u.LastLoginAt, u.ID)
	if err != nil {
		return err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return db.ErrNotFound
	}
	return nil
}

func (p *PostgresDB) DeleteUser(ctx context.Context, id string) error {
	res, err := p.db.ExecContext(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return db.ErrNotFound
	}
	return nil
}

func (p *PostgresDB) ListUsers(ctx context.Context, filter db.UserFilter) ([]domain.User, int64, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	if filter.Query != "" {
		conditions = append(conditions, fmt.Sprintf("(LOWER(email) LIKE $%d OR metadata::text ILIKE $%d)", argIdx, argIdx))
		searchTerm := "%" + strings.ToLower(filter.Query) + "%"
		args = append(args, searchTerm)
		argIdx++
	}

	if filter.Role != nil {
		conditions = append(conditions, fmt.Sprintf("role = $%d", argIdx))
		args = append(args, string(*filter.Role))
		argIdx++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, string(*filter.Status))
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users %s", whereClause)
	var total int64
	if err := p.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	pageSize := filter.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	page := filter.Page
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	sortBy := "created_at"
	if filter.SortBy == "email" || filter.SortBy == "updated_at" {
		sortBy = filter.SortBy
	}
	sortOrder := "DESC"
	if strings.ToUpper(filter.SortOrder) == "ASC" {
		sortOrder = "ASC"
	}

	selectQuery := fmt.Sprintf(`SELECT id, email, password_hash, role, status, email_verified, metadata, created_at, updated_at, last_login_at
		FROM users %s ORDER BY %s %s LIMIT $%d OFFSET $%d`, whereClause, sortBy, sortOrder, argIdx, argIdx+1)

	args = append(args, pageSize, offset)

	rows, err := p.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var u domain.User
		var metaStr string
		var lastLogin sql.NullTime

		err := rows.Scan(
			&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status,
			&u.EmailVerified, &metaStr, &u.CreatedAt, &u.UpdatedAt, &lastLogin,
		)
		if err != nil {
			return nil, 0, err
		}
		if lastLogin.Valid {
			u.LastLoginAt = &lastLogin.Time
		}
		_ = u.SetMetadataFromJSON([]byte(metaStr))
		users = append(users, u)
	}

	return users, total, nil
}

func (p *PostgresDB) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func (p *PostgresDB) scanUser(row *sql.Row) (*domain.User, error) {
	var u domain.User
	var metaStr string
	var lastLogin sql.NullTime

	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status,
		&u.EmailVerified, &metaStr, &u.CreatedAt, &u.UpdatedAt, &lastLogin,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}

	if lastLogin.Valid {
		u.LastLoginAt = &lastLogin.Time
	}
	_ = u.SetMetadataFromJSON([]byte(metaStr))
	return &u, nil
}

// Session operations
func (p *PostgresDB) CreateSession(ctx context.Context, sess *domain.Session) error {
	query := `INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, client_ip, is_revoked, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := p.db.ExecContext(ctx, query,
		sess.ID, sess.UserID, sess.RefreshToken, sess.UserAgent, sess.ClientIP,
		sess.IsRevoked, sess.ExpiresAt, sess.CreatedAt, sess.UpdatedAt)
	return err
}

func (p *PostgresDB) GetSessionByID(ctx context.Context, id string) (*domain.Session, error) {
	query := `SELECT id, user_id, refresh_token_hash, user_agent, client_ip, is_revoked, expires_at, created_at, updated_at
		FROM sessions WHERE id = $1 LIMIT 1`

	return p.scanSession(p.db.QueryRowContext(ctx, query, id))
}

func (p *PostgresDB) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	query := `SELECT id, user_id, refresh_token_hash, user_agent, client_ip, is_revoked, expires_at, created_at, updated_at
		FROM sessions WHERE refresh_token_hash = $1 LIMIT 1`

	return p.scanSession(p.db.QueryRowContext(ctx, query, tokenHash))
}

func (p *PostgresDB) RevokeSession(ctx context.Context, id string) error {
	_, err := p.db.ExecContext(ctx, "UPDATE sessions SET is_revoked = TRUE, updated_at = $1 WHERE id = $2", time.Now().UTC(), id)
	return err
}

func (p *PostgresDB) RevokeAllUserSessions(ctx context.Context, userID string) error {
	_, err := p.db.ExecContext(ctx, "UPDATE sessions SET is_revoked = TRUE, updated_at = $1 WHERE user_id = $2", time.Now().UTC(), userID)
	return err
}

func (p *PostgresDB) DeleteExpiredSessions(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < $1", time.Now().UTC())
	return err
}

func (p *PostgresDB) scanSession(row *sql.Row) (*domain.Session, error) {
	var sess domain.Session
	err := row.Scan(
		&sess.ID, &sess.UserID, &sess.RefreshToken, &sess.UserAgent, &sess.ClientIP,
		&sess.IsRevoked, &sess.ExpiresAt, &sess.CreatedAt, &sess.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	return &sess, nil
}

// Verification tokens
func (p *PostgresDB) CreateVerificationToken(ctx context.Context, token *domain.VerificationToken) error {
	query := `INSERT INTO verification_tokens (id, user_id, email, token_hash, code, type, used, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := p.db.ExecContext(ctx, query,
		token.ID, token.UserID, token.Email, token.TokenHash, token.Code, string(token.Type),
		token.Used, token.ExpiresAt, token.CreatedAt)
	return err
}

func (p *PostgresDB) GetVerificationToken(ctx context.Context, tokenHash string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	query := `SELECT id, user_id, email, token_hash, code, type, used, expires_at, created_at
		FROM verification_tokens WHERE token_hash = $1 AND type = $2 AND used = FALSE LIMIT 1`

	return p.scanToken(p.db.QueryRowContext(ctx, query, tokenHash, string(tokenType)))
}

func (p *PostgresDB) GetVerificationCode(ctx context.Context, email string, code string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	query := `SELECT id, user_id, email, token_hash, code, type, used, expires_at, created_at
		FROM verification_tokens WHERE LOWER(email) = LOWER($1) AND code = $2 AND type = $3 AND used = FALSE LIMIT 1`

	return p.scanToken(p.db.QueryRowContext(ctx, query, email, code, string(tokenType)))
}

func (p *PostgresDB) MarkTokenUsed(ctx context.Context, id string) error {
	_, err := p.db.ExecContext(ctx, "UPDATE verification_tokens SET used = TRUE WHERE id = $1", id)
	return err
}

func (p *PostgresDB) DeleteExpiredTokens(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM verification_tokens WHERE expires_at < $1", time.Now().UTC())
	return err
}

func (p *PostgresDB) scanToken(row *sql.Row) (*domain.VerificationToken, error) {
	var vt domain.VerificationToken
	var tType string

	err := row.Scan(
		&vt.ID, &vt.UserID, &vt.Email, &vt.TokenHash, &vt.Code, &tType,
		&vt.Used, &vt.ExpiresAt, &vt.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	vt.Type = domain.TokenType(tType)
	return &vt, nil
}

// OAuth accounts
func (p *PostgresDB) CreateOAuthAccount(ctx context.Context, acc *domain.OAuthAccount) error {
	query := `INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, email, avatar_url, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := p.db.ExecContext(ctx, query,
		acc.ID, acc.UserID, string(acc.Provider), acc.ProviderUserID,
		acc.Email, acc.AvatarURL, acc.CreatedAt, acc.UpdatedAt)
	return err
}

func (p *PostgresDB) GetOAuthAccount(ctx context.Context, provider domain.OAuthProvider, providerUserID string) (*domain.OAuthAccount, error) {
	query := `SELECT id, user_id, provider, provider_user_id, email, avatar_url, created_at, updated_at
		FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2 LIMIT 1`

	var acc domain.OAuthAccount
	var prov string
	err := p.db.QueryRowContext(ctx, query, string(provider), providerUserID).Scan(
		&acc.ID, &acc.UserID, &prov, &acc.ProviderUserID, &acc.Email, &acc.AvatarURL, &acc.CreatedAt, &acc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	acc.Provider = domain.OAuthProvider(prov)
	return &acc, nil
}

func (p *PostgresDB) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]domain.OAuthAccount, error) {
	query := `SELECT id, user_id, provider, provider_user_id, email, avatar_url, created_at, updated_at
		FROM oauth_accounts WHERE user_id = $1`

	rows, err := p.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []domain.OAuthAccount
	for rows.Next() {
		var acc domain.OAuthAccount
		var prov string
		if err := rows.Scan(&acc.ID, &acc.UserID, &prov, &acc.ProviderUserID, &acc.Email, &acc.AvatarURL, &acc.CreatedAt, &acc.UpdatedAt); err != nil {
			return nil, err
		}
		acc.Provider = domain.OAuthProvider(prov)
		accounts = append(accounts, acc)
	}
	return accounts, nil
}

func (p *PostgresDB) DeleteOAuthAccount(ctx context.Context, id string) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM oauth_accounts WHERE id = $1", id)
	return err
}

// Audit logs
func (p *PostgresDB) CreateAuditLog(ctx context.Context, log *domain.AuditLog) error {
	query := `INSERT INTO audit_logs (id, user_id, action, ip_address, user_agent, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := p.db.ExecContext(ctx, query,
		log.ID, log.UserID, log.Action, log.IPAddress, log.UserAgent, log.Metadata, log.CreatedAt)
	return err
}

func (p *PostgresDB) ListAuditLogs(ctx context.Context, userID string, limit, offset int) ([]domain.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	var query string
	var args []interface{}

	if userID != "" {
		query = `SELECT id, user_id, action, ip_address, user_agent, metadata, created_at
			FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		args = append(args, userID, limit, offset)
	} else {
		query = `SELECT id, user_id, action, ip_address, user_agent, metadata, created_at
			FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2`
		args = append(args, limit, offset)
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []domain.AuditLog
	for rows.Next() {
		var l domain.AuditLog
		var uid sql.NullString
		if err := rows.Scan(&l.ID, &uid, &l.Action, &l.IPAddress, &l.UserAgent, &l.Metadata, &l.CreatedAt); err != nil {
			return nil, err
		}
		if uid.Valid {
			l.UserID = uid.String
		}
		logs = append(logs, l)
	}
	return logs, nil
}
