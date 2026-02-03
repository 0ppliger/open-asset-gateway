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

type EdgeTag struct {
	Type  oam.PropertyType `json:"type"`
	Property oam.Property  `json:"property"`
	Edge string            `json:"edge"`
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

func (api *ApiV1) createEdgeTag(w http.ResponseWriter, r *http.Request) {
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

	edge, err := api.store.FindEdgeById(api.ctx, input.Edge)
	if err != nil {
		http.Error(w, "Cannot find to edge: "+err.Error(), http.StatusBadRequest)
		return		
	}

	in_edge_tag := &dbt.EdgeTag{
		Property: input.Property,
		Edge: edge,
	}

	out_edge_tag, err := api.store.CreateEdgeTag(api.ctx, edge, in_edge_tag)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}

	res := Response{ Subject: out_edge_tag.ID, Action: "upserted" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))	
}

func (api *ApiV1) deleteEdgeTag(w http.ResponseWriter, r *http.Request) {	
	id := r.PathValue("id")
	
	if err := api.store.DeleteEdgeTag(api.ctx, id); err != nil {
		http.Error(w, "Failed to delete edge tag: "+err.Error(), http.StatusBadRequest)
		return
	}
	
	res := Response{ Subject: id, Action: "deleted" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))
}

func (api *ApiV1) updateEdgeTag(w http.ResponseWriter, r *http.Request) {
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

	
	edge, err := api.store.FindEdgeById(api.ctx, input.Edge)
	if err != nil {
		http.Error(w, "Cannot find to edge: "+err.Error(), http.StatusBadRequest)
		return		
	}

	in_edge_tag := &dbt.EdgeTag{
		ID: id,
		Property: input.Property,
		Edge: edge,
	}

	out_edge_tag, err := api.store.CreateEdgeTag(api.ctx, edge, in_edge_tag)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}

	res := Response{ Subject: out_edge_tag.ID, Action: "updated" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))	
}
