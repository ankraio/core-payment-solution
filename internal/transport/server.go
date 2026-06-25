package transport

import (
	"encoding/json"
	"net/http"

	"github.com/ankraio/core-payment-solution/internal/event"
)

type IngestHandler struct {
	OnBatch func(events []event.Event)
}

func (handler IngestHandler) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(responseWriter, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var batch event.Batch
	if decodeError := json.NewDecoder(request.Body).Decode(&batch); decodeError != nil {
		http.Error(responseWriter, "bad request", http.StatusBadRequest)
		return
	}
	if handler.OnBatch != nil {
		handler.OnBatch(batch.Events)
	}
	responseWriter.WriteHeader(http.StatusAccepted)
}
