package main

import (
	"encoding/json"
	"fmt"
	"errors"
	"net/http"
	"reflect"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

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

	if aux.ID == "" && aux.Property == nil {
		return errors.New(fmt.Sprintf("no data"))
	}

	if aux.Property == nil {
		return nil
	}

	if aux.Type == "" {
		return errors.New(fmt.Sprintf("no type provided"))
	}

	if aux.Edge == "" {
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

func (api *ApiV1) emitEdgeTag(w http.ResponseWriter, r *http.Request) {
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

	if input.Property == nil {
		if err := api.store.DeleteEdgeTag(api.ctx, input.ID); err != nil {
			http.Error(w, "Failed to delete edge tag: "+err.Error(), http.StatusBadRequest)
			return
		}
		
		res := Response{ Subject: input.ID, Action: "deleted" }
		json, _ := json.Marshal(res)
		w.Write([]byte(json))
		return
	}

	target_edge, err := api.store.FindEdgeById(api.ctx, input.Edge)
	if err != nil {
		http.Error(w, "Cannot find to entity: "+err.Error(), http.StatusBadRequest)
		return		
	}

	in_edge_tag := &dbt.EdgeTag{
		Property: input.Property,
		Edge: target_edge,
	}

	out_edge_tag, err := api.store.CreateEdgeTag(api.ctx, target_edge, in_edge_tag)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}

	res := Response{ Subject: out_edge_tag.ID, Action: "upserted" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))	
}
