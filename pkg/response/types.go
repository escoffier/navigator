package response

import (
	"fmt"

	json "github.com/json-iterator/go"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

// Implements modified Google JSON styleguide
// https://google.github.io/styleguide/jsoncstyleguide.xml
//
// Modification is as follows:
// If API returns a single object, put it under HTTPData.Item
// If API returns multiple objects, put them under HTTPData.Items
// If API returns additional meta-information, put it under CustomFields

type HTTPEnvelope struct {
	ApiVersion string     `json:"apiVersion"`
	Data       *HTTPData  `json:"data,omitempty"`
	Target     *TargetRef `json:"target,omitempty"`
	Error      *HTTPError `json:"error,omitempty"`
	// EnevlopeError is a special field to communicate any errors when using Functional Options pattern in response.go
	// It's not sent to the client.
	EnvelopeError string `json:"-"`
}

type HTTPData struct {
	Status           uint8                  `json:"status"`
	Kind             string                 `json:"kind,omitempty"`
	CheckId          string                 `json:"checkId,omitempty"`
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
	Items            json.RawMessage        `json:"items,omitempty"`
	Item             json.RawMessage        `json:"item,omitempty"`
	CustomFields     map[string]interface{} `json:"-"` // custom marshalling and unmarshalling
}

type TargetRef struct {
	Name string
	ID   string
	Link string
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
	I18Err  i18.ErrI18     `json:"i18Err"`
}

func (h *HTTPError) Error() string {
	return h.Message
}

func NewHttpError(code int, err error, subErros ...HTTPSubError) *HTTPError {
	return &HTTPError{
		Code:    code,
		Message: err.Error(),
		Errors:  subErros,
	}
}

// HTTPDataAlias is used to avoid infinite recursion when calling json.Marshal in custom marshaller.
type HTTPDataAlias HTTPData

// MarshalJSON is overriden to support custom fields
func (e HTTPData) MarshalJSON() ([]byte, error) {
	// We want to add any CustomFields into the HTTPData structure

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

	// add any custom fields to dict
	for k, v := range e.CustomFields {
		baseFieldsDict[k] = v
	}
	// 如果返回的是列表，就一定会有如下三个字段，即使数值是0，也应该序列化
	if e.Items != nil {
		baseFieldsDict["itemsPerPage"] = e.ItemsPerPage
		baseFieldsDict["totalItems"] = e.TotalItems
		baseFieldsDict["startIndex"] = e.StartIndex
	}

	// return marshalled dict
	return json.Marshal(baseFieldsDict)
}

func (e *HTTPData) UnmarshalJSON(input []byte) error {
	// We want to extract any CustomFields from HTTPData structure.
	// We do this by finding the set difference between known HTTPData fields
	// and the ones present in input.

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

	// obtain only Custom fields, which is a difference of dicts of all and only HTTPData fields
	customFields := make(map[string]interface{})
	for key, val := range allFields {
		if _, ok := dataFields[key]; ok {
			// key in both
		} else {
			// key belongs to Item
			customFields[key] = val
		}
	}
	e.CustomFields = customFields

	// set Item and Items fields using raw json
	e.Item = dataStructFields.Item
	e.Items = dataStructFields.Items

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

func (e HTTPData) String() string {

	// Simplify values of Item and Items

	// Potentially we could use reflection here.
	type SimplifiedHTTPData struct {
		Kind             string
		Etag             string
		Lang             string
		Updated          string
		Deleted          bool
		CurrentItemCount int64
		ItemsPerPage     int64
		StartIndex       int64
		TotalItems       int64
		PageIndex        int64
		TotalPages       int64
		CustomFields     map[string]interface{}
		Item             string
		Items            string
	}

	itemOrNil := "<nil>"
	if e.Item != nil {
		itemOrNil = "<payload-bytes>"
	}
	itemsOrNil := "<nil>"
	if e.Items != nil {
		itemsOrNil = "<payload-bytes>"
	}

	simp := SimplifiedHTTPData{
		Kind:             e.Kind,
		Etag:             e.Etag,
		Lang:             e.Lang,
		Updated:          e.Updated,
		Deleted:          e.Deleted,
		CurrentItemCount: e.CurrentItemCount,
		ItemsPerPage:     e.ItemsPerPage,
		StartIndex:       e.StartIndex,
		TotalItems:       e.TotalItems,
		PageIndex:        e.PageIndex,
		TotalPages:       e.TotalPages,
		CustomFields:     e.CustomFields,
		Item:             itemOrNil,
		Items:            itemsOrNil,
	}
	return fmt.Sprintf("%+v", simp)
}

func (e HTTPEnvelope) String() string {
	dataOrNil := "<nil>"
	errOrNil := "<nil>"
	if e.Data != nil {
		dataOrNil = fmt.Sprintf("%+v", *e.Data)
	}
	if e.Error != nil {
		errOrNil = fmt.Sprintf("%+v", *e.Error)
	}

	return fmt.Sprintf("{ApiVersion:%v Data:%v Error:%v}", e.ApiVersion, dataOrNil, errOrNil)
}
