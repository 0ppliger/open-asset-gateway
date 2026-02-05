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
)

var relationTypes = map[oam.RelationType]reflect.Type{
	oam.BasicDNSRelation : reflect.TypeOf(oam_dns.BasicDNSRelation{}),
	oam.PortRelation     : reflect.TypeOf(oam_general.PortRelation{}),
	oam.PrefDNSRelation  : reflect.TypeOf(oam_dns.PrefDNSRelation{}),
	oam.SimpleRelation   : reflect.TypeOf(oam_general.SimpleRelation{}),
	oam.SRVDNSRelation   : reflect.TypeOf(oam_dns.SRVDNSRelation{}),
}

type Edge struct {
	ID         string           `json:"id",omitempty`
	CreatedAt  time.Time        `json:"created_at",omitempty`
	LastSeen   time.Time        `json:"last_seen",omitempty`
	Type       oam.RelationType `json:"type"`
	Relation   oam.Relation     `json:"relation"`
	FromEntity string           `json:"from_entity"`
	ToEntity   string           `json:"to_entity"`
}

func (e Edge) JSON() []byte {
	json_encoded, _ := json.Marshal(e)
	return json_encoded
}

func (e Edge) ToStore(from_entity *dbt.Entity, to_entity *dbt.Entity) *dbt.Edge {
	return &dbt.Edge{
		ID:         e.ID,
		CreatedAt:  e.CreatedAt,
		LastSeen:   e.LastSeen,
		Relation:   e.Relation,
		FromEntity: from_entity,
		ToEntity:   to_entity,
	}
}

func EdgeFromStore(e *dbt.Edge) Edge {
	return Edge{
		ID:         e.ID,
		CreatedAt:  e.CreatedAt,
		LastSeen:   e.LastSeen,
		Relation:   e.Relation,
		Type:       e.Relation.RelationType(),
		FromEntity: e.FromEntity.ID,
		ToEntity:   e.ToEntity.ID,
	}
}

func (a *Edge) UnmarshalJSON(data []byte) error {
	type Alias Edge
	aux := &struct {
		Relation json.RawMessage `json:"relation",omitempty`
		*Alias
	}{
		Alias: (*Alias)(a),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	T, ok := relationTypes[aux.Type]
	if !ok {
		return errors.New(fmt.Sprintf("unsupported asset type: %s", aux.Type))
	}

	rel := reflect.New(T)

	if err := json.Unmarshal(aux.Relation, rel.Interface()); err != nil {
		return err
	}

	a.Relation = rel.Interface().(oam.Relation)
	return nil
}

func (api *ApiV1) CreateEdge(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "no body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var input Edge
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	from_entity, err := api.store.FindEntityById(api.ctx, input.FromEntity)
	if err != nil {
		http.Error(w, "Cannot find from entity: "+err.Error(), http.StatusBadRequest)
		return		
	}

	to_entity, err := api.store.FindEntityById(api.ctx, input.ToEntity)
	if err != nil {
		http.Error(w, "Cannot find to entity: "+err.Error(), http.StatusBadRequest)
		return		
	}
		
	out, err := api.store.CreateEdge(api.ctx, input.ToStore(from_entity, to_entity))
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}
	created_edge := EdgeFromStore(out)

	w.Write(created_edge.JSON())	
}


func (api *ApiV1) DeleteEdge(w http.ResponseWriter, r *http.Request) {	
	id := r.PathValue("id")

 	out, err := api.store.FindEdgeById(api.ctx, id)
	if err != nil {
		http.Error(w, "Cannot find edge: "+err.Error(), http.StatusBadRequest)
		return		
	}
	deleted_edge := EdgeFromStore(out)

	if err := api.store.DeleteEdge(api.ctx, id); err != nil {
		http.Error(w, "Failed to delete edge: "+err.Error(), http.StatusBadRequest)
		return
	}
	
	w.Write(deleted_edge.JSON())
}

func (api *ApiV1) UpdateEdge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	
	if r.Body == nil {
		http.Error(w, "no body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var input Edge
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err := api.store.FindEdgeById(api.ctx, id)
	if err != nil {
		http.Error(w, "Cannot find to edge: "+err.Error(), http.StatusBadRequest)
		return		
	}

	from_entity, err := api.store.FindEntityById(api.ctx, input.FromEntity)
	if err != nil {
		http.Error(w, "Cannot find from entity: "+err.Error(), http.StatusBadRequest)
		return		
	}

	to_entity, err := api.store.FindEntityById(api.ctx, input.ToEntity)
	if err != nil {
		http.Error(w, "Cannot find to entity: "+err.Error(), http.StatusBadRequest)
		return		
	}

	input.ID = id
	
	out, err := api.store.CreateEdge(api.ctx, input.ToStore(from_entity, to_entity))
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}
	updated_edge := EdgeFromStore(out)

	w.Write(updated_edge.JSON())	
}
