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
)

type EdgeTag struct {
	ID        string           `json:"id",omitempty`
	CreatedAt time.Time        `json:"created_at",omitempty`
	LastSeen  time.Time        `json:"last_seen",omitempty`
	Property  oam.Property     `json:"property"`
	Edge      string           `json:"edge"`
	Type      oam.PropertyType `json:"type"`
}

func (e EdgeTag) JSON() []byte {
	json_encoded, _ := json.Marshal(e)
	return json_encoded
}

func (e EdgeTag) ToStore() *dbt.EdgeTag {
	return &dbt.EdgeTag{
		ID:         e.ID,
		CreatedAt:  e.CreatedAt,
		LastSeen:   e.LastSeen,
		Property:   e.Property,
		Edge:       &dbt.Edge{ID: e.Edge},
	}
}

func EdgeTagFromStore(e *dbt.EdgeTag) EdgeTag {
	return EdgeTag{
		ID:         e.ID,
		CreatedAt:  e.CreatedAt,
		LastSeen:   e.LastSeen,
		Property:   e.Property,
		Type:       e.Property.PropertyType(),
		Edge:       e.Edge.ID,
	}
}

func (a *EdgeTag) UnmarshalJSON(data []byte) error {
	type Alias EdgeTag
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

func (api *ApiV1) CreateEdgeTag(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "no body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var input EdgeTag
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err := api.store.FindEdgeById(api.ctx, input.Edge)
	if err != nil {
		http.Error(w, "Cannot find to edge: "+err.Error(), http.StatusBadRequest)
		return		
	}

	edge_tag := input.ToStore()
	
	out, err := api.store.CreateEdgeTag(api.ctx, edge_tag.Edge, edge_tag)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}
	created_edge_tag := EdgeTagFromStore(out)

	w.Write(created_edge_tag.JSON())	
}

func (api *ApiV1) DeleteEdgeTag(w http.ResponseWriter, r *http.Request) {	
	id := r.PathValue("id")

	out, err := api.store.FindEdgeTagById(api.ctx, id)
	if err != nil {
		http.Error(w, "Cannot find edge tag: "+err.Error(), http.StatusBadRequest)
		return		
	}
	deleted_edge_tag := EdgeTagFromStore(out)

	
	if err := api.store.DeleteEdgeTag(api.ctx, id); err != nil {
		http.Error(w, "Failed to delete edge tag: "+err.Error(), http.StatusBadRequest)
		return
	}
	
	w.Write(deleted_edge_tag.JSON())
}

func (api *ApiV1) UpdateEdgeTag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	
	if r.Body == nil {
		http.Error(w, "no body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var input EdgeTag
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err := api.store.FindEdgeTagById(api.ctx, id)
	if err != nil {
		http.Error(w, "Cannot find to edge tag: "+err.Error(), http.StatusBadRequest)
		return		
	}

	
	_, err = api.store.FindEdgeById(api.ctx, input.Edge)
	if err != nil {
		http.Error(w, "Cannot find to edge: "+err.Error(), http.StatusBadRequest)
		return		
	}

	input.ID = id
	edge_tag := input.ToStore()
	
	out, err := api.store.CreateEdgeTag(api.ctx, edge_tag.Edge, edge_tag)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}	
	updated_edge_tag := EdgeTagFromStore(out)

	w.Write(updated_edge_tag.JSON())	
}
