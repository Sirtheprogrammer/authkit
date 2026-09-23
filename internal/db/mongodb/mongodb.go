package mongodb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"authkit/internal/config"
	"authkit/internal/db"
	"authkit/internal/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoDB implements db.Database for MongoDB NoSQL database
type MongoDB struct {
	cfg        config.DatabaseConfig
	client     *mongo.Client
	database   *mongo.Database
	usersCol   *mongo.Collection
	sessCol    *mongo.Collection
	tokensCol  *mongo.Collection
	oauthCol   *mongo.Collection
	auditCol   *mongo.Collection
}

// New creates a new MongoDB adapter
func New(cfg config.DatabaseConfig) *MongoDB {
	return &MongoDB{cfg: cfg}
}

func (m *MongoDB) Type() string {
	return "mongodb"
}

func (m *MongoDB) Connect(ctx context.Context) error {
	uri := m.cfg.URL
	if uri == "" {
		host := m.cfg.Host
		if host == "" {
			host = "localhost"
		}
		port := m.cfg.Port
		if port <= 0 {
			port = 27017
		}
		if m.cfg.User != "" && m.cfg.Password != "" {
			uri = fmt.Sprintf("mongodb://%s:%s@%s:%d", m.cfg.User, m.cfg.Password, host, port)
		} else {
			uri = fmt.Sprintf("mongodb://%s:%d", host, port)
		}
	}

	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to connect to mongodb: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return fmt.Errorf("failed to ping mongodb: %w", err)
	}

	dbName := m.cfg.Database
	if dbName == "" {
		dbName = "authkit"
	}

	m.client = client
	m.database = client.Database(dbName)
	m.usersCol = m.database.Collection("users")
	m.sessCol = m.database.Collection("sessions")
	m.tokensCol = m.database.Collection("verification_tokens")
	m.oauthCol = m.database.Collection("oauth_accounts")
	m.auditCol = m.database.Collection("audit_logs")

	return nil
}

func (m *MongoDB) Ping(ctx context.Context) error {
	if m.client == nil {
		return fmt.Errorf("mongodb client is not connected")
	}
	return m.client.Ping(ctx, nil)
}

func (m *MongoDB) Close() error {
	if m.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return m.client.Disconnect(ctx)
	}
	return nil
}

func (m *MongoDB) Migrate(ctx context.Context) error {
	// Create indexes for users
	_, err := m.usersCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "email", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "role", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "status", Value: 1}},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create users indexes: %w", err)
	}

	// Create indexes for sessions
	_, err = m.sessCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "refresh_token_hash", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create sessions indexes: %w", err)
	}

	// Create indexes for verification tokens
	_, err = m.tokensCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "token_hash", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "email", Value: 1}, {Key: "code", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create verification tokens indexes: %w", err)
	}

	// Create indexes for OAuth accounts
	_, err = m.oauthCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "provider", Value: 1}, {Key: "provider_user_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create oauth indexes: %w", err)
	}

	// Create indexes for audit logs
	_, err = m.auditCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "created_at", Value: -1}},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create audit logs indexes: %w", err)
	}

	return nil
}

// User CRUD
func (m *MongoDB) CreateUser(ctx context.Context, u *domain.User) error {
	if u.Metadata == nil {
		u.Metadata = make(map[string]interface{})
	}

	_, err := m.usersCol.InsertOne(ctx, u)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return db.ErrDuplicateEmail
		}
		return err
	}
	return nil
}

func (m *MongoDB) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	var u domain.User
	err := m.usersCol.FindOne(ctx, bson.M{"_id": id}).Decode(&u)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	if u.Metadata == nil {
		u.Metadata = make(map[string]interface{})
	}
	return &u, nil
}

func (m *MongoDB) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	var u domain.User
	pattern := fmt.Sprintf("^%s$", strings.ToLower(email))
	err := m.usersCol.FindOne(ctx, bson.M{"email": bson.M{"$regex": pattern, "$options": "i"}}).Decode(&u)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	if u.Metadata == nil {
		u.Metadata = make(map[string]interface{})
	}
	return &u, nil
}

func (m *MongoDB) UpdateUser(ctx context.Context, u *domain.User) error {
	if u.Metadata == nil {
		u.Metadata = make(map[string]interface{})
	}

	update := bson.M{
		"$set": bson.M{
			"email":          u.Email,
			"password_hash":  u.PasswordHash,
			"role":           u.Role,
			"status":         u.Status,
			"email_verified": u.EmailVerified,
			"metadata":       u.Metadata,
			"updated_at":     u.UpdatedAt,
			"last_login_at":  u.LastLoginAt,
		},
	}

	res, err := m.usersCol.UpdateOne(ctx, bson.M{"_id": u.ID}, update)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return db.ErrNotFound
	}
	return nil
}

func (m *MongoDB) DeleteUser(ctx context.Context, id string) error {
	res, err := m.usersCol.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return db.ErrNotFound
	}
	// Cascade delete sessions and tokens
	_, _ = m.sessCol.DeleteMany(ctx, bson.M{"user_id": id})
	_, _ = m.tokensCol.DeleteMany(ctx, bson.M{"user_id": id})
	_, _ = m.oauthCol.DeleteMany(ctx, bson.M{"user_id": id})
	return nil
}

func (m *MongoDB) ListUsers(ctx context.Context, filter db.UserFilter) ([]domain.User, int64, error) {
	query := bson.M{}

	if filter.Query != "" {
		regexPattern := bson.M{"$regex": filter.Query, "$options": "i"}
		query["$or"] = []bson.M{
			{"email": regexPattern},
		}
	}

	if filter.Role != nil {
		query["role"] = *filter.Role
	}

	if filter.Status != nil {
		query["status"] = *filter.Status
	}

	total, err := m.usersCol.CountDocuments(ctx, query)
	if err != nil {
		return nil, 0, err
	}

	pageSize := int64(filter.PageSize)
	if pageSize <= 0 {
		pageSize = 20
	}
	page := int64(filter.Page)
	if page <= 0 {
		page = 1
	}
	skip := (page - 1) * pageSize

	sortOrder := -1
	if strings.ToUpper(filter.SortOrder) == "ASC" {
		sortOrder = 1
	}
	sortBy := "created_at"
	if filter.SortBy == "email" || filter.SortBy == "updated_at" {
		sortBy = filter.SortBy
	}

	findOptions := options.Find().
		SetSort(bson.D{{Key: sortBy, Value: sortOrder}}).
		SetLimit(pageSize).
		SetSkip(skip)

	cursor, err := m.usersCol.Find(ctx, query, findOptions)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var users []domain.User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, 0, err
	}

	for i := range users {
		if users[i].Metadata == nil {
			users[i].Metadata = make(map[string]interface{})
		}
	}

	return users, total, nil
}

func (m *MongoDB) CountUsers(ctx context.Context) (int64, error) {
	return m.usersCol.CountDocuments(ctx, bson.M{})
}

// Session operations
func (m *MongoDB) CreateSession(ctx context.Context, sess *domain.Session) error {
	_, err := m.sessCol.InsertOne(ctx, sess)
	return err
}

func (m *MongoDB) GetSessionByID(ctx context.Context, id string) (*domain.Session, error) {
	var s domain.Session
	err := m.sessCol.FindOne(ctx, bson.M{"_id": id}).Decode(&s)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

func (m *MongoDB) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	var s domain.Session
	err := m.sessCol.FindOne(ctx, bson.M{"refresh_token_hash": tokenHash}).Decode(&s)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

func (m *MongoDB) RevokeSession(ctx context.Context, id string) error {
	_, err := m.sessCol.UpdateOne(ctx, bson.M{"_id": id}, bson.M{
		"$set": bson.M{"is_revoked": true, "updated_at": time.Now().UTC()},
	})
	return err
}

func (m *MongoDB) RevokeAllUserSessions(ctx context.Context, userID string) error {
	_, err := m.sessCol.UpdateMany(ctx, bson.M{"user_id": userID}, bson.M{
		"$set": bson.M{"is_revoked": true, "updated_at": time.Now().UTC()},
	})
	return err
}

func (m *MongoDB) DeleteExpiredSessions(ctx context.Context) error {
	_, err := m.sessCol.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now().UTC()},
	})
	return err
}

// Verification tokens
func (m *MongoDB) CreateVerificationToken(ctx context.Context, token *domain.VerificationToken) error {
	_, err := m.tokensCol.InsertOne(ctx, token)
	return err
}

func (m *MongoDB) GetVerificationToken(ctx context.Context, tokenHash string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	var vt domain.VerificationToken
	err := m.tokensCol.FindOne(ctx, bson.M{
		"token_hash": tokenHash,
		"type":       tokenType,
		"used":       false,
	}).Decode(&vt)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	return &vt, nil
}

func (m *MongoDB) GetVerificationCode(ctx context.Context, email string, code string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	var vt domain.VerificationToken
	pattern := fmt.Sprintf("^%s$", strings.ToLower(email))
	err := m.tokensCol.FindOne(ctx, bson.M{
		"email": bson.M{"$regex": pattern, "$options": "i"},
		"code":  code,
		"type":  tokenType,
		"used":  false,
	}).Decode(&vt)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	return &vt, nil
}

func (m *MongoDB) MarkTokenUsed(ctx context.Context, id string) error {
	_, err := m.tokensCol.UpdateOne(ctx, bson.M{"_id": id}, bson.M{
		"$set": bson.M{"used": true},
	})
	return err
}

func (m *MongoDB) DeleteExpiredTokens(ctx context.Context) error {
	_, err := m.tokensCol.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now().UTC()},
	})
	return err
}

// OAuth accounts
func (m *MongoDB) CreateOAuthAccount(ctx context.Context, acc *domain.OAuthAccount) error {
	_, err := m.oauthCol.InsertOne(ctx, acc)
	return err
}

func (m *MongoDB) GetOAuthAccount(ctx context.Context, provider domain.OAuthProvider, providerUserID string) (*domain.OAuthAccount, error) {
	var acc domain.OAuthAccount
	err := m.oauthCol.FindOne(ctx, bson.M{
		"provider":          provider,
		"provider_user_id": providerUserID,
	}).Decode(&acc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	return &acc, nil
}

func (m *MongoDB) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]domain.OAuthAccount, error) {
	cursor, err := m.oauthCol.Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var accounts []domain.OAuthAccount
	if err := cursor.All(ctx, &accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (m *MongoDB) DeleteOAuthAccount(ctx context.Context, id string) error {
	_, err := m.oauthCol.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// Audit logs
func (m *MongoDB) CreateAuditLog(ctx context.Context, log *domain.AuditLog) error {
	_, err := m.auditCol.InsertOne(ctx, log)
	return err
}

func (m *MongoDB) ListAuditLogs(ctx context.Context, userID string, limit, offset int) ([]domain.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	query := bson.M{}
	if userID != "" {
		query["user_id"] = userID
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(offset))

	cursor, err := m.auditCol.Find(ctx, query, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []domain.AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}
