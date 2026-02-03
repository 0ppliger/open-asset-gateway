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
	oam_net "github.com/owasp-amass/open-asset-model/network"
	oam_org "github.com/owasp-amass/open-asset-model/org"
	oam_url "github.com/owasp-amass/open-asset-model/url"
	oam_cert "github.com/owasp-amass/open-asset-model/certificate"
	oam_pf "github.com/owasp-amass/open-asset-model/platform"
	oam_contact "github.com/owasp-amass/open-asset-model/contact"
	oam_file "github.com/owasp-amass/open-asset-model/file"
	oam_financial "github.com/owasp-amass/open-asset-model/financial"
	oam_general "github.com/owasp-amass/open-asset-model/general"
	oam_people "github.com/owasp-amass/open-asset-model/people"
	oam_reg "github.com/owasp-amass/open-asset-model/registration"
	oam_account "github.com/owasp-amass/open-asset-model/account"
)

var assetTypes = map[oam.AssetType]reflect.Type{
	oam.Account          : reflect.TypeOf(oam_account.Account{}),
	oam.AutnumRecord     : reflect.TypeOf(oam_reg.AutnumRecord{}),
	oam.AutonomousSystem : reflect.TypeOf(oam_net.AutonomousSystem{}),
	oam.ContactRecord    : reflect.TypeOf(oam_contact.ContactRecord{}),
	oam.DomainRecord     : reflect.TypeOf(oam_reg.DomainRecord{}),
	oam.File             : reflect.TypeOf(oam_file.File{}),
	oam.FQDN             : reflect.TypeOf(oam_dns.FQDN{}),
	oam.FundsTransfer    : reflect.TypeOf(oam_financial.FundsTransfer{}),
	oam.Identifier       : reflect.TypeOf(oam_general.Identifier{}),
	oam.IPAddress        : reflect.TypeOf(oam_net.IPAddress{}),
	oam.IPNetRecord      : reflect.TypeOf(oam_reg.IPNetRecord{}),
	oam.Location         : reflect.TypeOf(oam_contact.Location{}),
	oam.Netblock         : reflect.TypeOf(oam_net.Netblock{}),
	oam.Organization     : reflect.TypeOf(oam_org.Organization{}),
	oam.Person           : reflect.TypeOf(oam_people.Person{}),
	oam.Phone            : reflect.TypeOf(oam_contact.Phone{}),
	oam.Product          : reflect.TypeOf(oam_pf.Product{}),
	oam.ProductRelease   : reflect.TypeOf(oam_pf.ProductRelease{}),
	oam.Service          : reflect.TypeOf(oam_pf.Service{}),
	oam.TLSCertificate   : reflect.TypeOf(oam_cert.TLSCertificate{}),
	oam.URL              : reflect.TypeOf(oam_url.URL{}),
}

type Entity struct {
	Type  oam.AssetType `json:"type"`
	Asset oam.Asset     `json:"asset"`
}

func (a *Entity) UnmarshalJSON(data []byte) error {
	type Alias Entity
	aux := &struct {
		Asset json.RawMessage `json:"asset",omitempty`
		*Alias
	}{
		Alias: (*Alias)(a),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	T, ok := assetTypes[aux.Type]
	if !ok {
		return errors.New(fmt.Sprintf("unsupported asset type: %s", aux.Type))
	}

	asset := reflect.New(T)

	if err := json.Unmarshal(aux.Asset, asset.Interface()); err != nil {
		return err
	}

	a.Asset = asset.Interface().(oam.Asset)
	return nil
}

func (api *ApiV1) createEntity(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "no body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var input Entity
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	in_entity := &dbt.Entity{
		Asset: input.Asset,
	}
	
	out_entity, err := api.store.CreateEntity(api.ctx, in_entity)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}

	res := Response{ Subject: out_entity.ID, Action: "upserted" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))	
}

func (api *ApiV1) deleteEntity(w http.ResponseWriter, r *http.Request) {	
	id := r.PathValue("id")
	
	if err := api.store.DeleteEntity(api.ctx, id); err != nil {
		http.Error(w, "Failed to delete entity: "+err.Error(), http.StatusBadRequest)
		return
	}
	
	res := Response{ Subject: id, Action: "deleted" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))
}

func (api *ApiV1) updateEntity(w http.ResponseWriter, r *http.Request) {	
	id := r.PathValue("id")

	if r.Body == nil {
		http.Error(w, "no body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var input Entity
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err := api.store.FindEntityById(api.ctx, id)
	if err != nil {
		http.Error(w, "Cannot find to entity: "+err.Error(), http.StatusBadRequest)
		return		
	}

	in_entity := &dbt.Entity{
		ID: id,
		Asset: input.Asset,
	}
	
	out_entity, err := api.store.CreateEntity(api.ctx, in_entity)
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}
	
	res := Response{ Subject: out_entity.ID, Action: "updated" }
	json, _ := json.Marshal(res)
	w.Write([]byte(json))
}
