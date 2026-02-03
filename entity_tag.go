package main

import (
	"encoding/json"
	"fmt"
	"errors"
	"net/http"
	"reflect"
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
	Type  oam.PropertyType `json:"type"`
	Property oam.Property  `json:"property"`
	Entity string          `json:"entity"`
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

func (api *ApiV1) createEntityTag(w http.ResponseWriter, r *http.Request) {
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

	entity, err := api.store.FindEntityById(api.ctx, input.Entity)
	if err != nil {
		http.Error(w, "Cannot find to entity: "+err.Error(), http.StatusBadRequest)
		return		
	}

	in_entity_tag := &dbt.EntityTag{
		Property: input.Property,
		Entity: entity,
	}

	out_entity_tag, err := api.store.CreateEntityTag(api.ctx, entity, in_entity_tag)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}

	res := Response{ Subject: out_entity_tag.ID, Action: "upserted" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))	
}

func (api *ApiV1) deleteEntityTag(w http.ResponseWriter, r *http.Request) {	
	id := r.PathValue("id")
	
	if err := api.store.DeleteEntityTag(api.ctx, id); err != nil {
		http.Error(w, "Failed to delete entity tag: "+err.Error(), http.StatusBadRequest)
		return
	}
	
	res := Response{ Subject: id, Action: "deleted" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))
}

func (api *ApiV1) updateEntityTag(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Cannot find to entity tag: "+err.Error(), http.StatusBadRequest)
		return		
	}

	
	entity, err := api.store.FindEntityById(api.ctx, input.Entity)
	if err != nil {
		http.Error(w, "Cannot find to entity: "+err.Error(), http.StatusBadRequest)
		return		
	}

	in_entity_tag := &dbt.EntityTag{
		ID: id,
		Property: input.Property,
		Entity: entity,
	}

	out_entity_tag, err := api.store.CreateEntityTag(api.ctx, entity, in_entity_tag)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}

	res := Response{ Subject: out_entity_tag.ID, Action: "updated" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))	
}
