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
	
	mux.HandleFunc("/emit/entity", api.emitEntity)
	mux.HandleFunc("/emit/edge", api.emitEdge)
	mux.HandleFunc("/emit/entity_tag", api.emitEntityTag)
	mux.HandleFunc("/emit/edge_tag", api.emitEdgeTag)

	http.ListenAndServe(":8080", mux)
}
