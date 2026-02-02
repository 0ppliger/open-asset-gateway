package main

import (
	oam "github.com/owasp-amass/open-asset-model"
)

type Entity struct {
	ID    string        `json:"id",omitempty`
	Type  oam.AssetType `json:"type",omitempty`
	Asset oam.Asset     `json:"asset",omitempty`
}

type Edge struct {
	ID    string           `json:"id",omitempty`
	Type  oam.RelationType `json:"type",omitempty`
	Relation oam.Relation  `json:"relation",omitempty`
	From string            `json:"from",omitempty`
	To string              `json:"to",omitempty`
}

type EntityTag struct {
	ID    string           `json:"id",omitempty`
	Type  oam.PropertyType `json:"type",omitempty`
	Property oam.Property  `json:"property",omitempty`
	Entity string          `json:"target",omitempty`
}

type EdgeTag struct {
	ID    string           `json:"id",omitempty`
	Type  oam.PropertyType `json:"type",omitempty`
	Property oam.Property  `json:"property",omitempty`
	Edge string            `json:"target",omitempty`
}
