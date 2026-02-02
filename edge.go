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
)

var relationTypes = map[oam.RelationType]reflect.Type{
	oam.BasicDNSRelation : reflect.TypeOf(oam_dns.BasicDNSRelation{}),
	oam.PortRelation     : reflect.TypeOf(oam_general.PortRelation{}),
	oam.PrefDNSRelation  : reflect.TypeOf(oam_dns.PrefDNSRelation{}),
	oam.SimpleRelation   : reflect.TypeOf(oam_general.SimpleRelation{}),
	oam.SRVDNSRelation   : reflect.TypeOf(oam_dns.SRVDNSRelation{}),
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

	if aux.ID == "" && aux.Relation == nil {
		return errors.New(fmt.Sprintf("no data"))
	}

	if aux.Relation == nil {
		return nil
	}

	if aux.Type == "" {
		return errors.New(fmt.Sprintf("no type provided"))
	}

	if aux.From == "" || aux.To == "" {
		return errors.New(fmt.Sprintf("from entity and to entity are required"))
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

func (api *ApiV1) emitEdge(w http.ResponseWriter, r *http.Request) {
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

	if input.Relation == nil {
		if err := api.store.DeleteEdge(api.ctx, input.ID); err != nil {
			http.Error(w, "Failed to delete asset: "+err.Error(), http.StatusBadRequest)
			return
		}
		
		res := Response{ Subject: input.ID, Action: "deleted" }
		json, _ := json.Marshal(res)
		w.Write([]byte(json))
		return
	}

	from_entity, err := api.store.FindEntityById(api.ctx, input.From)
	if err != nil {
		http.Error(w, "Cannot find from entity: "+err.Error(), http.StatusBadRequest)
		return		
	}

	to_entity, err := api.store.FindEntityById(api.ctx, input.To)
	if err != nil {
		http.Error(w, "Cannot find to entity: "+err.Error(), http.StatusBadRequest)
		return		
	}
	
	in_edge := &dbt.Edge{
		ID: input.ID,
		Relation: input.Relation,
		FromEntity: from_entity,
		ToEntity: to_entity,
	}
	
	out_edge, err := api.store.CreateEdge(api.ctx, in_edge)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}

	res := Response{ Subject: out_edge.ID, Action: "upserted" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))	
}
