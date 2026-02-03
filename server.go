package main

import (
	"fmt"
	"net/http"
	"context"
	"github.com/owasp-amass/asset-db/repository/neo4j"
)


func main() {
	mux := http.NewServeMux()

	store, err := neo4j.New(neo4j.Neo4j, "bolt://neo4j:password@localhost:7687/neo4j")
	if err != nil {
		fmt.Println("Unable to connect to asset store: "+err.Error())
		return		
	}

	api := &ApiV1{
		ctx: context.Background(),
		store: store,
	}
	
	mux.HandleFunc("POST /emit/entity", api.createEntity)
	mux.HandleFunc("DELETE /emit/entity/{id}", api.deleteEntity)
	mux.HandleFunc("PUT /emit/entity/{id}", api.updateEntity)
	
	mux.HandleFunc("POST /emit/edge", api.createEdge)
	mux.HandleFunc("DELETE /emit/edge/{id}", api.deleteEdge)
	mux.HandleFunc("PUT /emit/edge/{id}", api.updateEdge)
	
	mux.HandleFunc("POST /emit/entity_tag", api.createEntityTag)
	mux.HandleFunc("DELETE /emit/entity_tag/{id}", api.deleteEntityTag)
	mux.HandleFunc("PUT /emit/entity_tag/{id}", api.updateEntityTag)

	mux.HandleFunc("POST /emit/edge_tag", api.createEdgeTag)
	mux.HandleFunc("DELETE /emit/edge_tag/{id}", api.deleteEdgeTag)
	mux.HandleFunc("PUT /emit/edge_tag/{id}", api.updateEdgeTag)

	http.ListenAndServe(":8080", mux)
}
