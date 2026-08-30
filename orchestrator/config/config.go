package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	// Server
	Port string
	Env  string

	// Database
	DatabaseURL string

	// Redis
	RedisAddr     string
	RedisPassword string

	// Auth
	JWTSecret      string
	JWTExpiryHours int

	// Worker
	WorkerToken  string
	WorkerImage  string
	DockerNetwork string

	// Scan defaults
	DefaultMaxContainers int
	DefaultMaxRetries    int

	// Storage
	StorageType      string
	StorageLocalPath string

	// Nuclei
	NucleiEnabled       bool
	NucleiTemplatesPath string

	// AI
	AIEnabled  bool
	AIGRPCAddr string

	// Debug console (TEMPORARY) — exposes /api/v1/debug/* log & job endpoints.
	// Disable in hardened deployments with DEBUG_CONSOLE=false.
	DebugConsole bool
}

func Load() (*Config, error) {
	cfg := &Config{
		Port:                getEnv("PORT", "8080"),
		Env:                 getEnv("ENV", "development"),
		DatabaseURL:         requireEnv("DATABASE_URL"),
		RedisAddr:           getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:       getEnv("REDIS_PASSWORD", ""),
		JWTSecret:           requireEnv("JWT_SECRET"),
		JWTExpiryHours:      getEnvInt("JWT_EXPIRY_HOURS", 24),
		WorkerToken:         requireEnv("WORKER_TOKEN"),
		WorkerImage:         getEnv("WORKER_IMAGE", "harbore-worker:latest"),
		DockerNetwork:       getEnv("DOCKER_NETWORK", "harbore_default"),
		DefaultMaxContainers: getEnvInt("DEFAULT_MAX_CONTAINERS", 10),
		DefaultMaxRetries:   getEnvInt("DEFAULT_MAX_RETRIES", 3),
		StorageType:         getEnv("STORAGE_TYPE", "local"),
		StorageLocalPath:    getEnv("STORAGE_LOCAL_PATH", "./data/evidence"),
		NucleiEnabled:       getEnvBool("NUCLEI_ENABLED", true),
		NucleiTemplatesPath: getEnv("NUCLEI_TEMPLATES_PATH", "/nuclei-templates"),
		AIEnabled:           getEnvBool("AI_ENABLED", false),
		AIGRPCAddr:          getEnv("AI_GRPC_ADDR", "ai:50051"),
		DebugConsole:        getEnvBool("DEBUG_CONSOLE", true),
	}

	if cfg.JWTSecret == "changeme_jwt_secret_minimum_64_chars_here" {
		return nil, fmt.Errorf("JWT_SECRET must be changed from the default value")
	}

	return cfg, nil
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", key))
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return fallback
}
