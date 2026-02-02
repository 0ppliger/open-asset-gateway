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

	if aux.ID == "" && aux.Property == nil {
		return errors.New(fmt.Sprintf("no data"))
	}

	if aux.Property == nil {
		return nil
	}

	if aux.Type == "" {
		return errors.New(fmt.Sprintf("no type provided"))
	}

	if aux.Entity == "" {
		return errors.New(fmt.Sprintf("target is required"))
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

func (api *ApiV1) emitEntityTag(w http.ResponseWriter, r *http.Request) {
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

	if input.Property == nil {
		if err := api.store.DeleteEntityTag(api.ctx, input.ID); err != nil {
			http.Error(w, "Failed to delete entity tag: "+err.Error(), http.StatusBadRequest)
			return
		}
		
		res := Response{ Subject: input.ID, Action: "deleted" }
		json, _ := json.Marshal(res)
		w.Write([]byte(json))
		return
	}

	target_entity, err := api.store.FindEntityById(api.ctx, input.Entity)
	if err != nil {
		http.Error(w, "Cannot find to entity: "+err.Error(), http.StatusBadRequest)
		return		
	}

	in_entity_tag := &dbt.EntityTag{
		Property: input.Property,
		Entity: target_entity,
	}

	out_entity_tag, err := api.store.CreateEntityTag(api.ctx, target_entity, in_entity_tag)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}

	res := Response{ Subject: out_entity_tag.ID, Action: "upserted" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))	
}
