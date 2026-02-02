package main

import (
	"context"
	"github.com/owasp-amass/asset-db/repository"
)

type ApiV1 struct {
	ctx context.Context
	store repository.Repository
}

type Response struct {
	Subject string `json:"subject"`
	Action string `json:"action"`
}

