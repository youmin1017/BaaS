package configs

import (
	"crypto/rsa"
	"fmt"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/joho/godotenv/autoload"
)

type Config struct {
	DatabaseURL string

	Keycloak struct {
		ClientId     string
		ClientSecret string
		Issuer       string
		RedirectURL  string
	}
	Jwt struct {
		PrivateKey *rsa.PrivateKey
		PublicKey  *rsa.PublicKey
		Issuer     string
		ExpireIn   int
	}
}

func LoadConfig() *Config {
	c := &Config{}

	Host := os.Getenv("DATABASE_HOST")
	Port := os.Getenv("DATABASE_PORT")
	DbName := os.Getenv("DATABASE_NAME")
	User := os.Getenv("DATABASE_USER")
	Password := os.Getenv("DATABASE_PASSWORD")
	c.DatabaseURL = fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s sslmode=disable",
		User,
		Password,
		Host,
		Port,
		DbName,
	)

	c.Keycloak.ClientId = os.Getenv("KEYCLOAK_CLIENT_ID")
	c.Keycloak.ClientSecret = os.Getenv("KEYCLOAK_CLIENT_SECRET")
	c.Keycloak.Issuer = os.Getenv("KEYCLOAK_ISSUER")
	c.Keycloak.RedirectURL = os.Getenv("KEYCLOAK_REDIRECT_URL")

	var err error
	c.Jwt.PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(os.Getenv("JWT_PRIVATE_KEY")))
	if err != nil {
		panic(fmt.Sprintf("Failed to parse private key %s", err))
	}
	c.Jwt.PublicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(os.Getenv("JWT_PUBLIC_KEY")))
	if err != nil {
		panic(fmt.Sprintf("Failed to parse public key %s", err))
	}
	c.Jwt.ExpireIn = func() int {
		valueStr := os.Getenv("JWT_EXPIRE_IN")
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
		return 3600
	}()
	c.Jwt.Issuer = os.Getenv("JWT_ISSUER")

	return c
}
