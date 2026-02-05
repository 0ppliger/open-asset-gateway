package main

import (
	"context"

	"github.com/owasp-amass/asset-db/repository"
)

type ApiV1 struct {
	ctx context.Context
	store repository.Repository
	bus *EventBus
}

type Serializable interface {
	JSON() []byte
}
