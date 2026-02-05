package main

import (
	"encoding/json"
	"fmt"
	"errors"
	"net/http"
	"reflect"
	"time"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oam_dns "github.com/owasp-amass/open-asset-model/dns"
	oam_general "github.com/owasp-amass/open-asset-model/general"
	oam_pf "github.com/owasp-amass/open-asset-model/platform"
)

var propertyTypes = map[oam.PropertyType]reflect.Type{
	oam.DNSRecordProperty : reflect.TypeOf(oam_dns.DNSRecordProperty{}),
	oam.SimpleProperty    : reflect.TypeOf(oam_general.SimpleProperty{}),
	oam.SourceProperty    : reflect.TypeOf(oam_general.SourceProperty{}),
	oam.VulnProperty      : reflect.TypeOf(oam_pf.VulnProperty{}),
}

type EntityTag struct {
	ID        string           `json:"id",omitempty`
	CreatedAt time.Time        `json:"created_at",omitempty`
	LastSeen  time.Time        `json:"last_seen",omitempty`
	Type      oam.PropertyType `json:"type"`
	Property  oam.Property     `json:"property"`
	Entity    string           `json:"entity"`
}

func (e EntityTag) JSON() []byte {
	json_encoded, _ := json.Marshal(e)
	return json_encoded
}

func (e EntityTag) ToStore() *dbt.EntityTag {
	return &dbt.EntityTag{
		ID:         e.ID,
		CreatedAt:  e.CreatedAt,
		LastSeen:   e.LastSeen,
		Property:   e.Property,
		Entity:     &dbt.Entity{ID: e.Entity},
	}
}

func EntityTagFromStore(e *dbt.EntityTag) EntityTag {
	return EntityTag{
		ID:         e.ID,
		CreatedAt:  e.CreatedAt,
		LastSeen:   e.LastSeen,
		Property:   e.Property,
		Type:       e.Property.PropertyType(),
		Entity:     e.Entity.ID,
	}
}

func (a *EntityTag) UnmarshalJSON(data []byte) error {
	type Alias EntityTag
	aux := &struct {
		Property json.RawMessage `json:"property",omitempty`
		*Alias
	}{
		Alias: (*Alias)(a),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	T, ok := propertyTypes[aux.Type]
	if !ok {
		return errors.New(fmt.Sprintf("unsupported asset type: %s", aux.Type))
	}

	prop := reflect.New(T)

	if err := json.Unmarshal(aux.Property, prop.Interface()); err != nil {
		return err
	}

	a.Property = prop.Interface().(oam.Property)
	return nil
}

func (api *ApiV1) CreateEntityTag(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "no body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var input EntityTag
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err := api.store.FindEntityById(api.ctx, input.Entity)
	if err != nil {
		http.Error(w, "Cannot find entity tag: "+err.Error(), http.StatusBadRequest)
		return		
	}

	entity_tag := input.ToStore()

	out, err := api.store.CreateEntityTag(api.ctx, entity_tag.Entity, entity_tag)
	if err != nil {
		http.Error(w, "Failed to upsert entity: "+err.Error(), http.StatusBadRequest)
		return
	}
	created_entity_tag := EntityTagFromStore(out)

	w.Write(created_entity_tag.JSON())	
}

func (api *ApiV1) DeleteEntityTag(w http.ResponseWriter, r *http.Request) {	
	id := r.PathValue("id")

	out, err := api.store.FindEntityTagById(api.ctx, id)
	if err != nil {
		http.Error(w, "Cannot find entity tag: "+err.Error(), http.StatusBadRequest)
		return		
	}
	delete_entity_tag := EntityTagFromStore(out)
	
	if err := api.store.DeleteEntityTag(api.ctx, id); err != nil {
		http.Error(w, "Failed to delete entity tag: "+err.Error(), http.StatusBadRequest)
		return
	}
	
	w.Write(delete_entity_tag.JSON())
}

func (api *ApiV1) UpdateEntityTag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	
	if r.Body == nil {
		http.Error(w, "no body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var input EntityTag
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err := api.store.FindEntityTagById(api.ctx, id)
	if err != nil {
		http.Error(w, "Cannot find entity tag: "+err.Error(), http.StatusBadRequest)
		return		
	}

	
	_, err = api.store.FindEntityById(api.ctx, input.Entity)
	if err != nil {
		http.Error(w, "Cannot find entity: "+err.Error(), http.StatusBadRequest)
		return		
	}

	input.ID = id
	entity_tag := input.ToStore()

	out, err := api.store.CreateEntityTag(api.ctx, entity_tag.Entity, entity_tag)
	if err != nil {
		http.Error(w, "Failed to update entity: "+err.Error(), http.StatusBadRequest)
		return
	}
	updated_entity_tag := EntityTagFromStore(out)
	
	w.Write(updated_entity_tag.JSON())	
}
