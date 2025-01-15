package services

import (
	"baas-auth/internal/configs"
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	DB *pgxpool.Pool
}

func InitService(config *configs.Config) *Service {
	db, err := pgxpool.New(context.Background(), config.DatabaseURL)

	if err != nil {
		panic(err)
	}

	service := &Service{}
	service.DB = db

	return service
}

func (s *Service) CreateUserWithUUID(userID uuid.UUID, email string) error {
	var dbUserID uuid.UUID
	err := s.DB.QueryRow(context.Background(), "INSERT INTO auth.user(uid, email) VALUES($1, $2) ON CONFLICT (uid) DO NOTHING RETURNING uid", userID, email).Scan(&dbUserID)

	if err == pgx.ErrNoRows {
		return nil
	}

	return err
}
