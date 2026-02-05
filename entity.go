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
	ID        string        `json:"id",omitempty`
	CreatedAt time.Time     `json:"created_at",omitempty`
	LastSeen  time.Time     `json:"last_seen",omitempty`
	Asset     oam.Asset     `json:"asset"`
	Type      oam.AssetType `json:"type"`
}

func (e Entity) JSON() []byte {
	json_encoded, _ := json.Marshal(e)
	return json_encoded
}

func (e Entity) ToStore() *dbt.Entity {
	return &dbt.Entity{
		ID:        e.ID,
		CreatedAt: e.CreatedAt,
		LastSeen:  e.LastSeen,
		Asset:     e.Asset,
	}
}

func EntityFromStore(e *dbt.Entity) Entity {
	return Entity{
		ID:        e.ID,
		CreatedAt: e.CreatedAt,
		LastSeen:  e.LastSeen,
		Asset:     e.Asset,
		Type:      e.Asset.AssetType(),
	}
}

func (a *Entity) UnmarshalJSON(data []byte) error {
	type Alias Entity
	aux := &struct {
		Asset json.RawMessage `json:"asset"`
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

func (api *ApiV1) CreateEntity(w http.ResponseWriter, r *http.Request) {
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
	
	out, err := api.store.CreateEntity(api.ctx, input.ToStore())
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}
	created_entity := EntityFromStore(out)
	
	api.bus.Publish(EntityCreated, created_entity)

	w.Write(created_entity.JSON())	
}

func (api *ApiV1) DeleteEntity(w http.ResponseWriter, r *http.Request) {	
	id := r.PathValue("id")

	out, err := api.store.FindEntityById(api.ctx, id)
	if err != nil {
		http.Error(w, "Cannot find entity: "+err.Error(), http.StatusBadRequest)
		return		
	}
	deleted_entity := EntityFromStore(out)
	
	if err := api.store.DeleteEntity(api.ctx, id); err != nil {
		http.Error(w, "Failed to delete entity: "+err.Error(), http.StatusBadRequest)
		return
	}

	api.bus.Publish(EntityDeleted, deleted_entity)
	
	w.Write(deleted_entity.JSON())
}

func (api *ApiV1) UpdateEntity(w http.ResponseWriter, r *http.Request) {	
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

	input.ID = id
	
	out, err := api.store.CreateEntity(api.ctx, input.ToStore())
	if err != nil {
		http.Error(w, "Failed to upsert asset: "+err.Error(), http.StatusBadRequest)
		return
	}
	updated_entity := EntityFromStore(out)

	api.bus.Publish(EntityUpdated, updated_entity)
	
	w.Write(updated_entity.JSON())
}
