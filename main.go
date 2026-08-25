package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"golang-fiber-jwt-auth/handler"
	"golang-fiber-jwt-auth/logs"
	"golang-fiber-jwt-auth/repository"
	"golang-fiber-jwt-auth/service"

	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

func main() {
	initConfig()

	db := initPostgres()
	defer db.Close()

	redisClient := initRedis()
	defer redisClient.Close()

	accessSecret := []byte(viper.GetString("jwt.access_secret"))
	refreshSecret := []byte(viper.GetString("jwt.refresh_secret"))
	accessTTL := time.Duration(viper.GetInt("jwt.access_ttl_minutes")) * time.Minute
	refreshTTL := time.Duration(viper.GetInt("jwt.refresh_ttl_hours")) * time.Hour

	userRepo := repository.NewUserRepositoryDB(db)
	refreshRepo := repository.NewRefreshTokenRepositoryRedis(redisClient)

	authSvc := service.NewAuthService(userRepo, refreshRepo, accessSecret, refreshSecret, accessTTL, refreshTTL)
	authHdlr := handler.NewAuthHandler(authSvc)

	app := fiber.New()

	app.Post("/auth/register", authHdlr.Register)
	app.Post("/auth/login", authHdlr.Login)
	app.Post("/auth/refresh", authHdlr.Refresh)
	app.Post("/auth/logout", authHdlr.Logout)
	app.Get("/me", handler.JWTMiddleware(accessSecret), authHdlr.Me)

	port := viper.GetString("app.port")
	logs.Info("server started on port " + port)
	if err := app.Listen(":" + port); err != nil {
		logs.Error(err)
		os.Exit(1)
	}
}

func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("read config: %w", err))
	}
}

func initPostgres() *sqlx.DB {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		viper.GetString("db.host"),
		viper.GetInt("db.port"),
		viper.GetString("db.user"),
		viper.GetString("db.password"),
		viper.GetString("db.name"),
		viper.GetString("db.sslmode"),
	)

	db, err := sqlx.Open("postgres", dsn)
	if err != nil {
		panic(fmt.Errorf("open postgres: %w", err))
	}
	if err := db.Ping(); err != nil {
		panic(fmt.Errorf("ping postgres: %w", err))
	}

	return db
}

func initRedis() *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     viper.GetString("redis.addr"),
		Password: viper.GetString("redis.password"),
		DB:       viper.GetInt("redis.db"),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		panic(fmt.Errorf("ping redis: %w", err))
	}

	return client
}
