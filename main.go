// Prappser Spaces - Backend service for hosting spaces for Prappser apps
// Copyright (C) 2025 Prappser Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	_ "github.com/lib/pq"
	"github.com/prappser/prappser-spaces/internal"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/health"
	"github.com/prappser/prappser-spaces/internal/invitation"
	"github.com/prappser/prappser-spaces/internal/keys"
	"github.com/prappser/prappser-spaces/internal/space"
	"github.com/prappser/prappser-spaces/internal/storage"
	"github.com/prappser/prappser-spaces/internal/setup"
	"github.com/prappser/prappser-spaces/internal/status"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/prappser/prappser-spaces/internal/websocket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// spaceLookupAdapter adapts space.SpaceRepository to user.SpaceLookup.
type spaceLookupAdapter struct {
	repo space.SpaceRepository
}

// spaceCreatorAdapter adapts space.SpaceService to user.SpaceCreator.
type spaceCreatorAdapter struct {
	service *space.SpaceService
}

func (a *spaceCreatorAdapter) CreateSpace(name string, userPublicKey *string) error {
	_, err := a.service.CreateSpace(name, userPublicKey)
	return err
}

func (a *spaceLookupAdapter) GetByUserPublicKey(publicKey string) (*user.SpaceInfo, error) {
	s, err := a.repo.GetByUserPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, nil
	}
	return &user.SpaceInfo{ID: s.ID}, nil
}

func initLogging() {
	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		level = "info"
	}

	switch strings.ToLower(level) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		log.Warn().Str("level", level).Msg("Unknown log level, defaulting to info")
	}

	log.Info().Str("level", level).Msg("Logging initialized")
}

func main() {
	initLogging()

	config, err := internal.LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading config")
		return
	}

	db, err := internal.NewDB()
	if err != nil {
		log.Fatal().Err(err).Msg("Error initializing database")
		return
	}

	keyRepo := keys.NewKeyRepository(db)
	keyService := keys.NewKeyService(keyRepo, config.MasterPassword)
	if err := keyService.Initialize(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize space keys")
		return
	}

	privateKey := keyService.PrivateKey()
	publicKey := keyService.PublicKey()

	userRepository := user.NewUserRepository(db)

	// Debug: log registered users at startup
	rows, err := db.Query("SELECT public_key, username, role FROM users")
	if err != nil {
		log.Error().Err(err).Msg("Failed to query users for debug log")
	} else {
		defer rows.Close()
		count := 0
		for rows.Next() {
			var pk, uname, role string
			if err := rows.Scan(&pk, &uname, &role); err == nil {
				log.Info().Str("publicKey", pk[:min(50, len(pk))]+"...").Str("username", uname).Str("role", role).Msg("[DEBUG] Registered user")
				count++
			}
		}
		log.Info().Int("count", count).Msg("[DEBUG] Total registered users")
	}

	spaceRepository := space.NewSpaceRepository(db)
	spaceService := space.NewSpaceService(spaceRepository, privateKey, publicKey)
	userService := user.NewUserService(userRepository, &spaceLookupAdapter{repo: spaceRepository}, config.Users, privateKey, publicKey)
	userEndpoints := user.NewEndpoints(userRepository, config.Users, privateKey, publicKey, userService, &spaceCreatorAdapter{service: spaceService})
	healthEndpoints := health.NewEndpoints("1.0.0")

	appRepository := application.NewRepository(db)
	storageRepo := storage.NewRepository(db)
	statusEndpoints := status.NewEndpoints("1.0.0", config.Storage.MaxFileSize, config.Storage.ChunkSize, storageRepo)

	wsHub := websocket.NewHub()
	go wsHub.Run()
	log.Info().Msg("WebSocket hub started")

	eventRepository := event.NewEventRepository(db)
	eventService := event.NewEventService(eventRepository, appRepository, wsHub)
	eventEndpoints := event.NewEventEndpoints(eventService)

	appService := application.NewApplicationService(appRepository)
	spacePublicKeyString := base64.StdEncoding.EncodeToString(publicKey)

	appEndpoints := application.NewApplicationEndpoints(appService, spacePublicKeyString)

	cleanupScheduler := event.NewCleanupScheduler(eventService, 7)
	cleanupScheduler.Start()
	log.Info().Msg("Event cleanup scheduler started")

	invitationRepository := invitation.NewInvitationRepository(db)
	invitationService := invitation.NewInvitationService(invitationRepository, privateKey, publicKey, appRepository, db, config.ExternalURL, userRepository, eventService)
	invitationEndpoints := invitation.NewInvitationEndpoints(invitationService)

	setupEndpoints := setup.NewSetupEndpoints(db)

	storageBackendConfig := &storage.BackendConfig{
		Type:        storage.StorageType(config.Storage.StorageType),
		LocalPath:   config.Storage.LocalPath,
		S3Endpoint:  config.Storage.S3Endpoint,
		S3Bucket:    config.Storage.S3Bucket,
		S3AccessKey: config.Storage.S3AccessKey,
		S3SecretKey: config.Storage.S3SecretKey,
		S3Region:    config.Storage.S3Region,
		S3UseSSL:    config.Storage.S3UseSSL,
		MaxFileSize: config.Storage.MaxFileSize,
		ChunkSize:   config.Storage.ChunkSize,
		ExternalURL: config.ExternalURL,
	}

	storageBackend, err := storage.NewBackend(storageBackendConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize storage backend")
		return
	}

	storageService := storage.NewService(storageRepo, storageBackend, config.Storage.MaxFileSize, config.ExternalURL)
	storageEndpoints := storage.NewEndpoints(storageService, appRepository, eventService, userRepository)
	log.Info().Str("storageType", config.Storage.StorageType).Msg("Storage service initialized")

	wsHandler := websocket.NewHandler(wsHub, userService)

	spaceEndpoints := space.NewSpaceEndpoints(spaceService, userRepository)

	requestHandler := internal.NewRequestHandler(config, userEndpoints, statusEndpoints, healthEndpoints, userService, appEndpoints, invitationEndpoints, eventEndpoints, setupEndpoints, storageEndpoints, wsHandler, spaceEndpoints)

	serverAddr := fmt.Sprintf(":%s", config.Port)
	log.Info().Str("addr", serverAddr).Msg("Starting HTTP server")
	server := &fasthttp.Server{
		Handler:            requestHandler,
		MaxRequestBodySize: int(config.Storage.MaxFileSize),
	}
	if err := server.ListenAndServe(serverAddr); err != nil {
		log.Fatal().Err(err).Msg("Error starting HTTP server")
	}
}
