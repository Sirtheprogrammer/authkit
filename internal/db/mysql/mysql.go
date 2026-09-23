package mysql

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
	mysqlDriver "github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
)

// MySQLDB implements db.Database for MySQL
type MySQLDB struct {
	cfg config.DatabaseConfig
	db  *sql.DB
}

// New creates a new MySQL database adapter
func New(cfg config.DatabaseConfig) *MySQLDB {
	return &MySQLDB{cfg: cfg}
}

func (m *MySQLDB) Type() string {
	return "mysql"
}

func (m *MySQLDB) Connect(ctx context.Context) error {
	dsn := m.cfg.URL
	if dsn == "" {
		host := m.cfg.Host
		if host == "" {
			host = "localhost"
		}
		port := m.cfg.Port
		if port <= 0 {
			port = 3306
		}
		user := m.cfg.User
		if user == "" {
			user = "root"
		}
		dbname := m.cfg.Database
		if dbname == "" {
			dbname = "authkit"
		}
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
			user, m.cfg.Password, host, port, dbname)
	}

	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("failed to open mysql database: %w", err)
	}

	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(5 * time.Minute)

	if err := conn.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping mysql database: %w", err)
	}

	m.db = conn
	return nil
}

func (m *MySQLDB) Ping(ctx context.Context) error {
	if m.db == nil {
		return fmt.Errorf("mysql database is not connected")
	}
	return m.db.PingContext(ctx)
}

func (m *MySQLDB) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

func (m *MySQLDB) Migrate(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(64) PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255),
			role VARCHAR(32) NOT NULL DEFAULT 'user',
			status VARCHAR(32) NOT NULL DEFAULT 'active',
			email_verified BOOLEAN NOT NULL DEFAULT FALSE,
			metadata JSON NOT NULL,
			created_at DATETIME(6) NOT NULL,
			updated_at DATETIME(6) NOT NULL,
			last_login_at DATETIME(6),
			INDEX idx_users_email (email),
			INDEX idx_users_role (role),
			INDEX idx_users_status (status)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

		`CREATE TABLE IF NOT EXISTS sessions (
			id VARCHAR(64) PRIMARY KEY,
			user_id VARCHAR(64) NOT NULL,
			refresh_token_hash VARCHAR(128) UNIQUE NOT NULL,
			user_agent TEXT,
			client_ip VARCHAR(64),
			is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
			expires_at DATETIME(6) NOT NULL,
			created_at DATETIME(6) NOT NULL,
			updated_at DATETIME(6) NOT NULL,
			INDEX idx_sessions_user_id (user_id),
			INDEX idx_sessions_token_hash (refresh_token_hash),
			CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

		`CREATE TABLE IF NOT EXISTS verification_tokens (
			id VARCHAR(64) PRIMARY KEY,
			user_id VARCHAR(64) NOT NULL,
			email VARCHAR(255) NOT NULL,
			token_hash VARCHAR(128) NOT NULL,
			code VARCHAR(32),
			type VARCHAR(32) NOT NULL,
			used BOOLEAN NOT NULL DEFAULT FALSE,
			expires_at DATETIME(6) NOT NULL,
			created_at DATETIME(6) NOT NULL,
			INDEX idx_vt_token_hash (token_hash),
			INDEX idx_vt_email_code (email, code),
			CONSTRAINT fk_vt_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

		`CREATE TABLE IF NOT EXISTS oauth_accounts (
			id VARCHAR(64) PRIMARY KEY,
			user_id VARCHAR(64) NOT NULL,
			provider VARCHAR(32) NOT NULL,
			provider_user_id VARCHAR(255) NOT NULL,
			email VARCHAR(255) NOT NULL,
			avatar_url TEXT,
			created_at DATETIME(6) NOT NULL,
			updated_at DATETIME(6) NOT NULL,
			UNIQUE KEY uq_provider_user (provider, provider_user_id),
			INDEX idx_oauth_user_id (user_id),
			CONSTRAINT fk_oauth_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

		`CREATE TABLE IF NOT EXISTS audit_logs (
			id VARCHAR(64) PRIMARY KEY,
			user_id VARCHAR(64),
			action VARCHAR(64) NOT NULL,
			ip_address VARCHAR(64),
			user_agent TEXT,
			metadata TEXT,
			created_at DATETIME(6) NOT NULL,
			INDEX idx_audit_user_id (user_id),
			INDEX idx_audit_created_at (created_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,
	}

	for _, q := range queries {
		if _, err := m.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("mysql migration failed on query: %w", err)
		}
	}

	return nil
}

// User CRUD
func (m *MySQLDB) CreateUser(ctx context.Context, u *domain.User) error {
	metaJSON, err := u.MetadataJSON()
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `INSERT INTO users (id, email, password_hash, role, status, email_verified, metadata, created_at, updated_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = m.db.ExecContext(ctx, query,
		u.ID, u.Email, u.PasswordHash, string(u.Role), string(u.Status),
		u.EmailVerified, string(metaJSON), u.CreatedAt, u.UpdatedAt, u.LastLoginAt)

	if err != nil {
		var myErr *mysqlDriver.MySQLError
		if errors.As(err, &myErr) && myErr.Number == 1062 {
			return db.ErrDuplicateEmail
		}
		return err
	}
	return nil
}

func (m *MySQLDB) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	query := `SELECT id, email, password_hash, role, status, email_verified, metadata, created_at, updated_at, last_login_at
		FROM users WHERE id = ? LIMIT 1`

	return m.scanUser(m.db.QueryRowContext(ctx, query, id))
}

func (m *MySQLDB) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `SELECT id, email, password_hash, role, status, email_verified, metadata, created_at, updated_at, last_login_at
		FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1`

	return m.scanUser(m.db.QueryRowContext(ctx, query, email))
}

func (m *MySQLDB) UpdateUser(ctx context.Context, u *domain.User) error {
	metaJSON, err := u.MetadataJSON()
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `UPDATE users SET
		email = ?, password_hash = ?, role = ?, status = ?,
		email_verified = ?, metadata = ?, updated_at = ?, last_login_at = ?
		WHERE id = ?`

	res, err := m.db.ExecContext(ctx, query,
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

func (m *MySQLDB) DeleteUser(ctx context.Context, id string) error {
	res, err := m.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
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

func (m *MySQLDB) ListUsers(ctx context.Context, filter db.UserFilter) ([]domain.User, int64, error) {
	var conditions []string
	var args []interface{}

	if filter.Query != "" {
		conditions = append(conditions, "(LOWER(email) LIKE ? OR metadata LIKE ?)")
		searchTerm := "%" + strings.ToLower(filter.Query) + "%"
		args = append(args, searchTerm, searchTerm)
	}

	if filter.Role != nil {
		conditions = append(conditions, "role = ?")
		args = append(args, string(*filter.Role))
	}

	if filter.Status != nil {
		conditions = append(conditions, "status = ?")
		args = append(args, string(*filter.Status))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users %s", whereClause)
	var total int64
	if err := m.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
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
		FROM users %s ORDER BY %s %s LIMIT ? OFFSET ?`, whereClause, sortBy, sortOrder)

	args = append(args, pageSize, offset)

	rows, err := m.db.QueryContext(ctx, selectQuery, args...)
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

func (m *MySQLDB) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	err := m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func (m *MySQLDB) scanUser(row *sql.Row) (*domain.User, error) {
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
func (m *MySQLDB) CreateSession(ctx context.Context, sess *domain.Session) error {
	query := `INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, client_ip, is_revoked, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := m.db.ExecContext(ctx, query,
		sess.ID, sess.UserID, sess.RefreshToken, sess.UserAgent, sess.ClientIP,
		sess.IsRevoked, sess.ExpiresAt, sess.CreatedAt, sess.UpdatedAt)
	return err
}

func (m *MySQLDB) GetSessionByID(ctx context.Context, id string) (*domain.Session, error) {
	query := `SELECT id, user_id, refresh_token_hash, user_agent, client_ip, is_revoked, expires_at, created_at, updated_at
		FROM sessions WHERE id = ? LIMIT 1`

	return m.scanSession(m.db.QueryRowContext(ctx, query, id))
}

func (m *MySQLDB) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	query := `SELECT id, user_id, refresh_token_hash, user_agent, client_ip, is_revoked, expires_at, created_at, updated_at
		FROM sessions WHERE refresh_token_hash = ? LIMIT 1`

	return m.scanSession(m.db.QueryRowContext(ctx, query, tokenHash))
}

func (m *MySQLDB) RevokeSession(ctx context.Context, id string) error {
	_, err := m.db.ExecContext(ctx, "UPDATE sessions SET is_revoked = TRUE, updated_at = ? WHERE id = ?", time.Now().UTC(), id)
	return err
}

func (m *MySQLDB) RevokeAllUserSessions(ctx context.Context, userID string) error {
	_, err := m.db.ExecContext(ctx, "UPDATE sessions SET is_revoked = TRUE, updated_at = ? WHERE user_id = ?", time.Now().UTC(), userID)
	return err
}

func (m *MySQLDB) DeleteExpiredSessions(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < ?", time.Now().UTC())
	return err
}

func (m *MySQLDB) scanSession(row *sql.Row) (*domain.Session, error) {
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
func (m *MySQLDB) CreateVerificationToken(ctx context.Context, token *domain.VerificationToken) error {
	query := `INSERT INTO verification_tokens (id, user_id, email, token_hash, code, type, used, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := m.db.ExecContext(ctx, query,
		token.ID, token.UserID, token.Email, token.TokenHash, token.Code, string(token.Type),
		token.Used, token.ExpiresAt, token.CreatedAt)
	return err
}

func (m *MySQLDB) GetVerificationToken(ctx context.Context, tokenHash string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	query := `SELECT id, user_id, email, token_hash, code, type, used, expires_at, created_at
		FROM verification_tokens WHERE token_hash = ? AND type = ? AND used = FALSE LIMIT 1`

	return m.scanToken(m.db.QueryRowContext(ctx, query, tokenHash, string(tokenType)))
}

func (m *MySQLDB) GetVerificationCode(ctx context.Context, email string, code string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	query := `SELECT id, user_id, email, token_hash, code, type, used, expires_at, created_at
		FROM verification_tokens WHERE LOWER(email) = LOWER(?) AND code = ? AND type = ? AND used = FALSE LIMIT 1`

	return m.scanToken(m.db.QueryRowContext(ctx, query, email, code, string(tokenType)))
}

func (m *MySQLDB) MarkTokenUsed(ctx context.Context, id string) error {
	_, err := m.db.ExecContext(ctx, "UPDATE verification_tokens SET used = TRUE WHERE id = ?", id)
	return err
}

func (m *MySQLDB) DeleteExpiredTokens(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, "DELETE FROM verification_tokens WHERE expires_at < ?", time.Now().UTC())
	return err
}

func (m *MySQLDB) scanToken(row *sql.Row) (*domain.VerificationToken, error) {
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
func (m *MySQLDB) CreateOAuthAccount(ctx context.Context, acc *domain.OAuthAccount) error {
	query := `INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, email, avatar_url, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := m.db.ExecContext(ctx, query,
		acc.ID, acc.UserID, string(acc.Provider), acc.ProviderUserID,
		acc.Email, acc.AvatarURL, acc.CreatedAt, acc.UpdatedAt)
	return err
}

func (m *MySQLDB) GetOAuthAccount(ctx context.Context, provider domain.OAuthProvider, providerUserID string) (*domain.OAuthAccount, error) {
	query := `SELECT id, user_id, provider, provider_user_id, email, avatar_url, created_at, updated_at
		FROM oauth_accounts WHERE provider = ? AND provider_user_id = ? LIMIT 1`

	var acc domain.OAuthAccount
	var prov string
	err := m.db.QueryRowContext(ctx, query, string(provider), providerUserID).Scan(
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

func (m *MySQLDB) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]domain.OAuthAccount, error) {
	query := `SELECT id, user_id, provider, provider_user_id, email, avatar_url, created_at, updated_at
		FROM oauth_accounts WHERE user_id = ?`

	rows, err := m.db.QueryContext(ctx, query, userID)
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

func (m *MySQLDB) DeleteOAuthAccount(ctx context.Context, id string) error {
	_, err := m.db.ExecContext(ctx, "DELETE FROM oauth_accounts WHERE id = ?", id)
	return err
}

// Audit logs
func (m *MySQLDB) CreateAuditLog(ctx context.Context, log *domain.AuditLog) error {
	query := `INSERT INTO audit_logs (id, user_id, action, ip_address, user_agent, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := m.db.ExecContext(ctx, query,
		log.ID, log.UserID, log.Action, log.IPAddress, log.UserAgent, log.Metadata, log.CreatedAt)
	return err
}

func (m *MySQLDB) ListAuditLogs(ctx context.Context, userID string, limit, offset int) ([]domain.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	var query string
	var args []interface{}

	if userID != "" {
		query = `SELECT id, user_id, action, ip_address, user_agent, metadata, created_at
			FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
		args = append(args, userID, limit, offset)
	} else {
		query = `SELECT id, user_id, action, ip_address, user_agent, metadata, created_at
			FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
	}

	rows, err := m.db.QueryContext(ctx, query, args...)
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
