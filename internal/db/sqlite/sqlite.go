package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"authkit/internal/db"
	"authkit/internal/domain"
	_ "modernc.org/sqlite"
)

// SQLiteDB implements the db.Database interface using modernc.org/sqlite (pure Go)
type SQLiteDB struct {
	filepath string
	db       *sql.DB
}

// New creates a new SQLite database adapter
func New(filepath string) *SQLiteDB {
	if filepath == "" {
		filepath = "./authkit.db"
	}
	return &SQLiteDB{filepath: filepath}
}

func (s *SQLiteDB) Type() string {
	return "sqlite"
}

func (s *SQLiteDB) Connect(ctx context.Context) error {
	dir := filepath.Dir(s.filepath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create sqlite dir %s: %w", dir, err)
		}
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", s.filepath)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("failed to open sqlite database: %w", err)
	}

	conn.SetMaxOpenConns(1) // SQLite single writer mode
	conn.SetMaxIdleConns(1)

	if err := conn.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	s.db = conn
	return nil
}

func (s *SQLiteDB) Ping(ctx context.Context) error {
	if s.db == nil {
		return fmt.Errorf("sqlite database is not connected")
	}
	return s.db.PingContext(ctx)
}

func (s *SQLiteDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *SQLiteDB) Migrate(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT,
			role TEXT NOT NULL DEFAULT 'user',
			status TEXT NOT NULL DEFAULT 'active',
			email_verified INTEGER NOT NULL DEFAULT 0,
			metadata TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			last_login_at DATETIME
		);`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
		`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);`,
		`CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);`,

		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			refresh_token_hash TEXT UNIQUE NOT NULL,
			user_agent TEXT,
			client_ip TEXT,
			is_revoked INTEGER NOT NULL DEFAULT 0,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(refresh_token_hash);`,

		`CREATE TABLE IF NOT EXISTS verification_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			email TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			code TEXT,
			type TEXT NOT NULL,
			used INTEGER NOT NULL DEFAULT 0,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_vt_token_hash ON verification_tokens(token_hash);`,
		`CREATE INDEX IF NOT EXISTS idx_vt_email_code ON verification_tokens(email, code);`,

		`CREATE TABLE IF NOT EXISTS oauth_accounts (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			provider TEXT NOT NULL,
			provider_user_id TEXT NOT NULL,
			email TEXT NOT NULL,
			avatar_url TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			UNIQUE(provider, provider_user_id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_user_id ON oauth_accounts(user_id);`,

		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			action TEXT NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			metadata TEXT,
			created_at DATETIME NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);`,
	}

	for _, q := range queries {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migration failed on query %s: %w", q, err)
		}
	}

	return nil
}

// User CRUD
func (s *SQLiteDB) CreateUser(ctx context.Context, u *domain.User) error {
	metaJSON, err := u.MetadataJSON()
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `INSERT INTO users (id, email, password_hash, role, status, email_verified, metadata, created_at, updated_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	verified := 0
	if u.EmailVerified {
		verified = 1
	}

	_, err = s.db.ExecContext(ctx, query,
		u.ID, u.Email, u.PasswordHash, string(u.Role), string(u.Status),
		verified, string(metaJSON), u.CreatedAt, u.UpdatedAt, u.LastLoginAt)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: users.email") {
			return db.ErrDuplicateEmail
		}
		return err
	}
	return nil
}

func (s *SQLiteDB) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	query := `SELECT id, email, password_hash, role, status, email_verified, metadata, created_at, updated_at, last_login_at
		FROM users WHERE id = ? LIMIT 1`

	return s.scanUser(s.db.QueryRowContext(ctx, query, id))
}

func (s *SQLiteDB) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `SELECT id, email, password_hash, role, status, email_verified, metadata, created_at, updated_at, last_login_at
		FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1`

	return s.scanUser(s.db.QueryRowContext(ctx, query, email))
}

func (s *SQLiteDB) UpdateUser(ctx context.Context, u *domain.User) error {
	metaJSON, err := u.MetadataJSON()
	if err != nil {
		metaJSON = []byte("{}")
	}

	verified := 0
	if u.EmailVerified {
		verified = 1
	}

	query := `UPDATE users SET
		email = ?, password_hash = ?, role = ?, status = ?,
		email_verified = ?, metadata = ?, updated_at = ?, last_login_at = ?
		WHERE id = ?`

	res, err := s.db.ExecContext(ctx, query,
		u.Email, u.PasswordHash, string(u.Role), string(u.Status),
		verified, string(metaJSON), u.UpdatedAt, u.LastLoginAt, u.ID)
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

func (s *SQLiteDB) DeleteUser(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
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

func (s *SQLiteDB) ListUsers(ctx context.Context, filter db.UserFilter) ([]domain.User, int64, error) {
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

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users %s", whereClause)
	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
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

	rows, err := s.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var u domain.User
		var verified int
		var metaStr string
		var lastLogin sql.NullTime

		err := rows.Scan(
			&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status,
			&verified, &metaStr, &u.CreatedAt, &u.UpdatedAt, &lastLogin,
		)
		if err != nil {
			return nil, 0, err
		}
		u.EmailVerified = verified == 1
		if lastLogin.Valid {
			u.LastLoginAt = &lastLogin.Time
		}
		_ = u.SetMetadataFromJSON([]byte(metaStr))
		users = append(users, u)
	}

	return users, total, nil
}

func (s *SQLiteDB) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func (s *SQLiteDB) scanUser(row *sql.Row) (*domain.User, error) {
	var u domain.User
	var verified int
	var metaStr string
	var lastLogin sql.NullTime

	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status,
		&verified, &metaStr, &u.CreatedAt, &u.UpdatedAt, &lastLogin,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}

	u.EmailVerified = verified == 1
	if lastLogin.Valid {
		u.LastLoginAt = &lastLogin.Time
	}
	_ = u.SetMetadataFromJSON([]byte(metaStr))
	return &u, nil
}

// Session operations
func (s *SQLiteDB) CreateSession(ctx context.Context, sess *domain.Session) error {
	query := `INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, client_ip, is_revoked, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	revoked := 0
	if sess.IsRevoked {
		revoked = 1
	}

	_, err := s.db.ExecContext(ctx, query,
		sess.ID, sess.UserID, sess.RefreshToken, sess.UserAgent, sess.ClientIP,
		revoked, sess.ExpiresAt, sess.CreatedAt, sess.UpdatedAt)
	return err
}

func (s *SQLiteDB) GetSessionByID(ctx context.Context, id string) (*domain.Session, error) {
	query := `SELECT id, user_id, refresh_token_hash, user_agent, client_ip, is_revoked, expires_at, created_at, updated_at
		FROM sessions WHERE id = ? LIMIT 1`

	return s.scanSession(s.db.QueryRowContext(ctx, query, id))
}

func (s *SQLiteDB) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	query := `SELECT id, user_id, refresh_token_hash, user_agent, client_ip, is_revoked, expires_at, created_at, updated_at
		FROM sessions WHERE refresh_token_hash = ? LIMIT 1`

	return s.scanSession(s.db.QueryRowContext(ctx, query, tokenHash))
}

func (s *SQLiteDB) RevokeSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sessions SET is_revoked = 1, updated_at = ? WHERE id = ?", time.Now().UTC(), id)
	return err
}

func (s *SQLiteDB) RevokeAllUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sessions SET is_revoked = 1, updated_at = ? WHERE user_id = ?", time.Now().UTC(), userID)
	return err
}

func (s *SQLiteDB) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < ?", time.Now().UTC())
	return err
}

func (s *SQLiteDB) scanSession(row *sql.Row) (*domain.Session, error) {
	var sess domain.Session
	var revoked int

	err := row.Scan(
		&sess.ID, &sess.UserID, &sess.RefreshToken, &sess.UserAgent, &sess.ClientIP,
		&revoked, &sess.ExpiresAt, &sess.CreatedAt, &sess.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	sess.IsRevoked = revoked == 1
	return &sess, nil
}

// Verification tokens
func (s *SQLiteDB) CreateVerificationToken(ctx context.Context, token *domain.VerificationToken) error {
	query := `INSERT INTO verification_tokens (id, user_id, email, token_hash, code, type, used, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	used := 0
	if token.Used {
		used = 1
	}

	_, err := s.db.ExecContext(ctx, query,
		token.ID, token.UserID, token.Email, token.TokenHash, token.Code, string(token.Type),
		used, token.ExpiresAt, token.CreatedAt)
	return err
}

func (s *SQLiteDB) GetVerificationToken(ctx context.Context, tokenHash string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	query := `SELECT id, user_id, email, token_hash, code, type, used, expires_at, created_at
		FROM verification_tokens WHERE token_hash = ? AND type = ? AND used = 0 LIMIT 1`

	return s.scanToken(s.db.QueryRowContext(ctx, query, tokenHash, string(tokenType)))
}

func (s *SQLiteDB) GetVerificationCode(ctx context.Context, email string, code string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	query := `SELECT id, user_id, email, token_hash, code, type, used, expires_at, created_at
		FROM verification_tokens WHERE LOWER(email) = LOWER(?) AND code = ? AND type = ? AND used = 0 LIMIT 1`

	return s.scanToken(s.db.QueryRowContext(ctx, query, email, code, string(tokenType)))
}

func (s *SQLiteDB) MarkTokenUsed(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE verification_tokens SET used = 1 WHERE id = ?", id)
	return err
}

func (s *SQLiteDB) DeleteExpiredTokens(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM verification_tokens WHERE expires_at < ?", time.Now().UTC())
	return err
}

func (s *SQLiteDB) scanToken(row *sql.Row) (*domain.VerificationToken, error) {
	var vt domain.VerificationToken
	var used int
	var tType string

	err := row.Scan(
		&vt.ID, &vt.UserID, &vt.Email, &vt.TokenHash, &vt.Code, &tType,
		&used, &vt.ExpiresAt, &vt.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	vt.Used = used == 1
	vt.Type = domain.TokenType(tType)
	return &vt, nil
}

// OAuth accounts
func (s *SQLiteDB) CreateOAuthAccount(ctx context.Context, acc *domain.OAuthAccount) error {
	query := `INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, email, avatar_url, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		acc.ID, acc.UserID, string(acc.Provider), acc.ProviderUserID,
		acc.Email, acc.AvatarURL, acc.CreatedAt, acc.UpdatedAt)
	return err
}

func (s *SQLiteDB) GetOAuthAccount(ctx context.Context, provider domain.OAuthProvider, providerUserID string) (*domain.OAuthAccount, error) {
	query := `SELECT id, user_id, provider, provider_user_id, email, avatar_url, created_at, updated_at
		FROM oauth_accounts WHERE provider = ? AND provider_user_id = ? LIMIT 1`

	var acc domain.OAuthAccount
	var prov string
	err := s.db.QueryRowContext(ctx, query, string(provider), providerUserID).Scan(
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

func (s *SQLiteDB) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]domain.OAuthAccount, error) {
	query := `SELECT id, user_id, provider, provider_user_id, email, avatar_url, created_at, updated_at
		FROM oauth_accounts WHERE user_id = ?`

	rows, err := s.db.QueryContext(ctx, query, userID)
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

func (s *SQLiteDB) DeleteOAuthAccount(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM oauth_accounts WHERE id = ?", id)
	return err
}

// Audit logs
func (s *SQLiteDB) CreateAuditLog(ctx context.Context, log *domain.AuditLog) error {
	query := `INSERT INTO audit_logs (id, user_id, action, ip_address, user_agent, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		log.ID, log.UserID, log.Action, log.IPAddress, log.UserAgent, log.Metadata, log.CreatedAt)
	return err
}

func (s *SQLiteDB) ListAuditLogs(ctx context.Context, userID string, limit, offset int) ([]domain.AuditLog, error) {
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

	rows, err := s.db.QueryContext(ctx, query, args...)
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
