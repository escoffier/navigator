package response

import (
	"encoding/json"
)

// Implements modified Google JSON styleguide
// https://google.github.io/styleguide/jsoncstyleguide.xml

type HTTPEnvelope struct {
	ApiVersion string     `json:"apiVersion"`
	Data       *HTTPData  `json:"data,omitempty"`
	Error      *HTTPError `json:"error,omitempty"`
	// EnevlopeError is a special field to communicate any errors when using Functional Options pattern in response.go
	// It's not sent to the client.
	EnvelopeError string `json:"-"`
}

type HTTPData struct {
	Kind             string                 `json:"kind,omitempty"`
	Etag             string                 `json:"etag,omitempty"`
	Lang             string                 `json:"lang,omitempty"`
	Updated          string                 `json:"updated,omitempty"`
	Deleted          bool                   `json:"deleted,omitempty"`
	CurrentItemCount int64                  `json:"currentItemCount,omitempty"`
	ItemsPerPage     int64                  `json:"itemsPerPage,omitempty"`
	StartIndex       int64                  `json:"startIndex,omitempty"`
	TotalItems       int64                  `json:"totalItems,omitempty"`
	PageIndex        int64                  `json:"pageIndex,omitempty"`
	TotalPages       int64                  `json:"totalPages,omitempty"`
	Items            interface{}            `json:"items,omitempty"`
	Item             json.RawMessage        `json:"-"` // custom marshalling and unmarshalling, see (HTTPData)(Un)MarshalJSON
	CustomFields     map[string]interface{} `json:"-"` // custom marshalling and TODO:unmarshalling, see (HTTPData)(Un)MarshalJSON
}

type HTTPSubError struct {
	Domain       string `json:"domain,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Message      string `json:"message,omitempty"`
	Location     string `json:"location,omitempty"`
	LocationType string `json:"locationType,omitempty"`
	ExtendedHelp string `json:"extendedHelp,omitempty"`
	SendReport   string `json:"sendReport,omitempty"`
}

// HTTPError tells the status and error
type HTTPError struct {
	// Status string `json:"status"`
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Errors  []HTTPSubError `json:"errors"`
}

// HTTPDataAlias is used to avoid infinite recursion when calling json.Marshal in custom marshaller.
type HTTPDataAlias HTTPData

// MarshalJSON is overriden to support custom fields
func (e HTTPData) MarshalJSON() ([]byte, error) {
	// This is kinda inefficient but I probably is good enough (we're IO bound I would think)

	// obtain dict from base struct
	// Note: this assumes that CustomFields is disabled using struct annotation `json:"-"`
	jsoned, err := json.Marshal(HTTPDataAlias(e))
	if err != nil {
		return []byte{}, err
	}
	var baseFieldsDict map[string]interface{}
	err = json.Unmarshal(jsoned, &baseFieldsDict)
	if err != nil {
		return []byte{}, err
	}

	// obtain dict from internal "Item" field
	// Note: this assumes that Item is disabled using struct annotation `json:"-"`
	jsonedItem, err := json.Marshal(e.Item)
	if err != nil {
		return []byte{}, err
	}
	var itemFields map[string]interface{}
	err = json.Unmarshal(jsonedItem, &itemFields)
	if err != nil {
		return []byte{}, err
	}

	// add any custom fields to dict
	for k, v := range e.CustomFields {
		baseFieldsDict[k] = v
	}
	// add fields from Item struct
	for k, v := range itemFields {
		baseFieldsDict[k] = v
	}

	return json.Marshal(baseFieldsDict)
}

func (e *HTTPData) UnmarshalJSON(input []byte) error {
	// This is kinda cancer... It's really hard to handle JSON styleguide in golang or I'm an idiot.
	// If somebody has a better idea here, I beg you, please fix this.

	// obtain all fields as dict
	var allFields map[string]interface{}
	err := json.Unmarshal(input, &allFields)
	if err != nil {
		return err
	}

	// obtain only fields of HTTPData which are in the struct definition
	var dataStructFields HTTPDataAlias
	err = json.Unmarshal(input, &dataStructFields)
	if err != nil {
		return err
	}

	onlyDataJSON, err := json.Marshal(dataStructFields)
	if err != nil {
		return err
	}

	var dataFields map[string]interface{}
	err = json.Unmarshal(onlyDataJSON, &dataFields)
	if err != nil {
		return err
	}

	// obtain only fields of Item, which is a difference of dicts of all and only HTTPData fields
	itemFields := make(map[string]interface{})
	for key, val := range allFields {
		if _, ok := dataFields[key]; ok {
			// key in both
		} else {
			// key belongs to Item
			itemFields[key] = val
		}
	}

	// marshal the fields of Item, because it's RawMessage (user needs to unmarshal to specific struct they want)
	onlyItemJSON, err := json.Marshal(itemFields)
	if err != nil {
		return err
	}
	e.Item = onlyItemJSON

	// set all the fields of HTTPData struct based on dict values
	// we don't check if key exists or if type is correct, but we probably should.
	e.Kind, _ = dataFields["kind"].(string)
	e.Etag, _ = dataFields["etag"].(string)
	e.Lang, _ = dataFields["lang"].(string)
	e.Updated, _ = dataFields["updated"].(string)
	e.Deleted, _ = dataFields["deleted"].(bool)
	e.CurrentItemCount, _ = dataFields["currentItemCount"].(int64)
	e.ItemsPerPage, _ = dataFields["itemsPerPage"].(int64)
	e.StartIndex, _ = dataFields["startIndex"].(int64)
	e.TotalItems, _ = dataFields["totalItems"].(int64)
	e.PageIndex, _ = dataFields["pageIndex"].(int64)
	e.TotalPages, _ = dataFields["totalPages"].(int64)

	return nil
}
