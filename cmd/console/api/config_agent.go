package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	"gitlab.com/piccolo_su/vegeta/pkg/heartbeat"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	agentCollection = "agents"
)

type agent struct {
	ID            primitive.ObjectID             `json:"id" bson:"_id, omitempty"`
	Name          string                         `json:"name"`
	Type          string                         `json:"type"`
	Namespace     string                         `json:"namespace"`
	Etcd          string                         `json:"etcd"`
	Running       bool                           `json:"running" bson:"-"`
	Heartbeats    map[string]heartbeat.Heartbeat `json:"heartbeats"`
	LastUpdatedAt int64                          `json:"lastUpdatedAt"`
	Yaml          string                         `json:"yaml,omitempty"`
}

// @Summary Create an agent entry with YAML
// @Description Create an agent entry with YAML
// @ID v1-config-agents-post
// @Produce json
// @Param name body string true "agent name"
// @Param type body string true "agent type: daemonset, scanner, sidecar"
// @Param namespace body string true "the namespace the agent is running in"
// @Param etcd body string true "the etcd endpoint: <host>:<port>"
// @Router /api/v1/config/agents [post]
//
// curl -d '{"type":"daemonset","name":"n","namespace":"vegeta","etcd":"http://127.0.0.1:2379"}'
//      -H "Authorization: BEARER <jwt>" -H "Content-Type: application/json"
//      -X POST http://localhost:8080/api/v1/config/agents
func (api *api) createAgent() http.HandlerFunc {
	type param struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Namespace string `json:"namespace"`
		Etcd      string `json:"etcd"`
	}
	type resp struct {
		AgentID string `json:"agentID"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// create yaml, and uuid
		// save all the params and the created yaml to the mongo
		param := &param{}
		err := json.NewDecoder(r.Body).Decode(param)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		newAgent := &agent{
			ID:        primitive.NewObjectIDFromTimestamp(time.Now()),
			Name:      param.Name,
			Type:      param.Type,
			Namespace: param.Namespace,
			Etcd:      param.Etcd,
			Yaml:      "Test",
		}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()
		insertResult, err := api.mongodb.Collection(agentCollection).InsertOne(ctx, newAgent)
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}

		response.Ok(w, response.WithItem(resp{
			AgentID: fmt.Sprintf("%v", insertResult.InsertedID),
		}))
	}
}

// @Summary Get the list of Agents
// @Description Get the list of Agents
// @ID v1-config-agents-get
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Router /api/v1/config/agents [get]
func (api *api) listAgents() http.HandlerFunc {
	type resp struct {
		Agents []agent `json:"agents"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		offset, limit := api.getOffsetAndLimit(r)

		opts := options.Find()
		opts.SetSkip(offset)
		opts.SetLimit(limit)

		cur, err := api.mongodb.Collection(agentCollection).Find(ctx, bson.D{}, opts)
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}
		defer cur.Close(ctx)

		resp := &resp{
			Agents: make([]agent, 0),
		}
		for cur.Next(ctx) {
			var elem agent
			err := cur.Decode(&elem)
			if err != nil {
				response.InternalError(w, err.Error())
				return
			}

			// remove the yaml from json
			elem.Yaml = ""

			// from etcd
			elem.Heartbeats, elem.LastUpdatedAt, elem.Running, err = heartbeat.GetAll(
				ctx, api.etcdClient, elem.ID.Hex())
			if err != nil {
				response.InternalError(w, err.Error())
				return
			}

			resp.Agents = append(resp.Agents, elem)
		}
		if err := cur.Err(); err != nil {
			response.InternalError(w, err.Error())
			return
		}

		response.Ok(w, response.WithItem(resp))
	}
}

func getAgentObjectIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	agentID := chi.URLParam(r, "agentID")
	if agentID == "" {
		return primitive.NilObjectID, errors.New("agentID is not provided")
	}
	return primitive.ObjectIDFromHex(agentID)
}

// @Summary Get an agent by agent ID
// @Description Get an agent
// @ID v1-config-agent-get
// @Produce json
// @Param agentID path string true "agent ID"
// @Param yaml query bool false "return yaml only if yaml = true"
// @Router /api/v1/config/agent/{agentID} [get]
func (api *api) getAgent() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get ObjectID
		agentObjectID, err := getAgentObjectIDFromURL(r)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		// from mongo
		var result agent
		err = api.mongodb.Collection(agentCollection).FindOne(
			ctx, bson.M{"_id": agentObjectID}).Decode(&result)
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}

		// if yaml only
		yamlOnly, err := param.QueryBool(r, "yaml")
		if err == nil && yamlOnly {
			// Header-Status-Payload
			w.Header().Set("Content-Type", "application/x-yaml")
			w.WriteHeader(200)
			_, err = w.Write([]byte(result.Yaml))
			if err != nil {
				response.InternalError(w, err.Error())
			}
			return
		}

		result.Yaml = ""
		result.Heartbeats, result.LastUpdatedAt, result.Running, err = heartbeat.GetAll(
			ctx, api.etcdClient, result.ID.Hex())
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}
		response.Ok(w, response.WithItem(result))
	}
}

// @Summary Delete an agent by agent ID
// @Description Get an agent
// @ID v1-config-agent-get
// @Produce json
// @Param agentID path string true "agent ID"
// @Param yaml query bool false "return yaml only if yaml = true"
// @Router /api/v1/config/agent/{agentID} [get]
func (api *api) deleteAgent() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get ObjectID
		agentObjectID, err := getAgentObjectIDFromURL(r)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		// delete from mongo
		_, err = api.mongodb.Collection(agentCollection).DeleteOne(
			ctx, bson.M{"_id": agentObjectID})
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}
		response.Ok(w)
	}
}
