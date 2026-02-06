package main

import (
	"net/http"
	"fmt"
	"sync"
)

type EventType int

const (
	EntityCreated EventType = iota
	EntityDeleted
	EntityUpdated
	EntityTouched
	EdgeCreated
	EdgeDeleted
	EdgeUpdated
	EdgeTouched
	EdgeTagCreated
	EdgeTagDeleted
	EdgeTagUpdated
	EdgeTagTouched
	EntityTagCreated
	EntityTagDeleted
	EntityTagUpdated
	EntityTagTouched
)

var eventName = map[EventType]string{
	EntityCreated: "EntityCreated",
	EntityDeleted: "EntityDeleted",
	EntityUpdated: "EntityUpdated",
	EntityTouched: "EntityTouched",
	EdgeCreated: "EdgeCreated",
	EdgeDeleted: "EdgeDeleted",
	EdgeUpdated: "EdgeUpdated",
	EdgeTouched: "EdgeTouched",
	EdgeTagCreated: "EdgeTagCreated",
	EdgeTagDeleted: "EdgeTagDeleted",
	EdgeTagUpdated: "EdgeTagUpdated",
	EdgeTagTouched: "EdgeTagTouched",
	EntityTagCreated: "EntityTagCreated",
	EntityTagDeleted: "EntityTagDeleted",
	EntityTagUpdated: "EntityTagUpdated",
	EntityTagTouched: "EntityTagTouched",
}

type ServerSentEvent struct {
	Event EventType
	Data Serializable
}

func (sse ServerSentEvent) Write(w http.ResponseWriter) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventName[sse.Event], sse.Data.JSON())
}

type EventBus struct {
	subscribers map[chan ServerSentEvent]bool
	mutex       sync.Mutex
}

func (bus *EventBus) AddSubscriber() chan ServerSentEvent {
	ch := make(chan ServerSentEvent)
	
	bus.mutex.Lock()
	bus.subscribers[ch] = true
	bus.mutex.Unlock()

	return ch
}

func (bus *EventBus) RemoveSubscriber(ch chan ServerSentEvent) {
	bus.mutex.Lock()
	delete(bus.subscribers, ch)
	bus.mutex.Unlock()
	close(ch)
}

func (bus *EventBus) Publish(event EventType, data Serializable) {

	sse := ServerSentEvent{
		Event: event,
		Data: data,
	}
	
	bus.mutex.Lock()
	defer bus.mutex.Unlock()
	for ch := range bus.subscribers {
		ch <- sse
	}
}

func (api *ApiV1) ListenEvents(w http.ResponseWriter, r *http.Request) {

	ch := api.bus.AddSubscriber()
	defer func() {
		api.bus.RemoveSubscriber(ch)
	}()
	
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	for {
		select {
		case sse := <-ch:
			sse.Write(w)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
