package status

import (
	"os"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

var startTime = time.Now()

type StorageUsageGetter interface {
	GetTotalUsedBytes() (int64, error)
}

type StatusEndpoints struct {
	version          string
	maxFileSizeBytes int64
	chunkSizeBytes   int64
	storageRepo      StorageUsageGetter
	externalURL      string
}

func NewEndpoints(version string, maxFileSizeBytes, chunkSizeBytes int64, storageRepo StorageUsageGetter, externalURL string) *StatusEndpoints {
	return &StatusEndpoints{
		version:          version,
		maxFileSizeBytes: maxFileSizeBytes,
		chunkSizeBytes:   chunkSizeBytes,
		storageRepo:      storageRepo,
		externalURL:      externalURL,
	}
}

type StatusResponse struct {
	Health           string `json:"health"`
	Version          string `json:"version"`
	MaxFileSizeBytes int64  `json:"maxFileSizeBytes"`
	ChunkSizeBytes   int64  `json:"chunkSizeBytes"`
	StorageUsedBytes int64  `json:"storageUsedBytes"`
}

func (se *StatusEndpoints) Status(ctx *fasthttp.RequestCtx) {
	var storageUsedBytes int64
	if se.storageRepo != nil {
		used, err := se.storageRepo.GetTotalUsedBytes()
		if err != nil {
			log.Error().Err(err).Msg("Failed to get storage used bytes")
		} else {
			storageUsedBytes = used
		}
	}

	response := StatusResponse{
		Health:           "OK",
		Version:          se.version,
		MaxFileSizeBytes: se.maxFileSizeBytes,
		ChunkSizeBytes:   se.chunkSizeBytes,
		StorageUsedBytes: storageUsedBytes,
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)

	responseJSON, err := json.Marshal(response)
	if err != nil {
		ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetBody(responseJSON)
}

type DebugEnvResponse struct {
	RailwayPublicDomain string            `json:"railwayPublicDomain"`
	Railway             map[string]string `json:"railway"`
	ExternalURLEnv      string            `json:"externalUrlEnv"`
	ConfigExternalURL   string            `json:"configExternalURL"`
	UptimeSeconds       int               `json:"uptimeSeconds"`
	Now                 string            `json:"now"`
	Host                string            `json:"host"`
	XForwardedHost      string            `json:"xForwardedHost"`
	XForwardedProto     string            `json:"xForwardedProto"`
}

func (se *StatusEndpoints) DebugEnv(ctx *fasthttp.RequestCtx) {
	response := DebugEnvResponse{
		RailwayPublicDomain: os.Getenv("RAILWAY_PUBLIC_DOMAIN"),
		Railway: map[string]string{
			"RAILWAY_PUBLIC_DOMAIN":    os.Getenv("RAILWAY_PUBLIC_DOMAIN"),
			"RAILWAY_STATIC_URL":       os.Getenv("RAILWAY_STATIC_URL"),
			"RAILWAY_PROJECT_ID":       os.Getenv("RAILWAY_PROJECT_ID"),
			"RAILWAY_SERVICE_ID":       os.Getenv("RAILWAY_SERVICE_ID"),
			"RAILWAY_ENVIRONMENT_NAME": os.Getenv("RAILWAY_ENVIRONMENT_NAME"),
		},
		ExternalURLEnv:    os.Getenv("EXTERNAL_URL"),
		ConfigExternalURL: se.externalURL,
		UptimeSeconds:     int(time.Since(startTime).Seconds()),
		Now:               time.Now().UTC().Format(time.RFC3339),
		Host:              string(ctx.Host()),
		XForwardedHost:    string(ctx.Request.Header.Peek("X-Forwarded-Host")),
		XForwardedProto:   string(ctx.Request.Header.Peek("X-Forwarded-Proto")),
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)

	responseJSON, err := json.Marshal(response)
	if err != nil {
		ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetBody(responseJSON)
}
