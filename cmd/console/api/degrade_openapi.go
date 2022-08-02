package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	v1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (api *api) degradeOpenAPI() func(chi.Router) {
	rate, err := strconv.Atoi(os.Getenv("OPENAPI_RATE_LIMIT_PER_MIN"))
	if err != nil || rate <= 0 {
		rate = 20
	}

	return func(r chi.Router) {
		r.With(RateLimitMiddleware(api.redisClient, int64(rate)))
		r.Post("/driftDefense", api.driftDefense())
	}
}

func upsertConfigMap(ctx context.Context, client *assets.Clientset, cm *v1.ConfigMap) error {
	_, err := client.CoreV1().ConfigMaps(cm.Namespace).Get(ctx, cm.Name, metav1.GetOptions{})
	if err != nil {
		if apierrs.IsNotFound(err) {
			_, err = client.CoreV1().ConfigMaps(cm.Namespace).Create(ctx, cm, metav1.CreateOptions{})
			if err != nil {
				logging.Get().Error().Err(err).Msg("create cm error")
				return err
			}
		}

		logging.Get().Error().Err(err).Msg("get cm error")
		return err
	}

	_, err = client.CoreV1().ConfigMaps(cm.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		logging.Get().Error().Err(err).Msg("update cm error")
	}

	return err
}

func (api *api) driftDefense() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		req := struct {
			ClusterKey string `json:"clusterKey"`
			IsRecover  bool   `json:"isRecover"`
		}{}

		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		myNamespace := os.Getenv("MY_POD_NAMESPACE")
		if myNamespace == "" {
			myNamespace = "tensorsec"
		}

		name := "ivan-degradation-controller"
		cm := &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: myNamespace,
			},
			Data: map[string]string{"driftDefense": "*"},
		}

		if req.IsRecover {
			cm.Data["driftDefense"] = ""
		}

		clusterManager, ok := k8s.GetClusterManager()
		if !ok {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("cluster manager not exist")))
			return
		}

		if req.ClusterKey == "" {
			// all cluster
			clusterManager.TraverseClient(func(key string, client *assets.Clientset) bool {
				if err = upsertConfigMap(ctx, client, cm); err != nil {
					logging.Get().Error().Err(err).Str("clusterKey", key).Msg("upsertConfigMap")
				}

				return true
			})
		} else {
			// specified cluster
			cli, ok := clusterManager.GetClient(req.ClusterKey)
			if !ok {
				logging.Get().Info().Str("clusterKey", req.ClusterKey).Msg("get k8s client failed")
				apperror.RespAndLog(w, ctx,
					apperror.NewAnError(http.StatusInternalServerError,
						errors.New("get k8s client failed")))
				return
			}

			if err = upsertConfigMap(ctx, cli, cm); err != nil {
				logging.Get().Error().Err(err).Str("clusterKey", req.ClusterKey).Msg("upsertConfigMap")
				apperror.RespAndLog(w, ctx,
					apperror.NewAnError(http.StatusInternalServerError,
						errors.New("driftDefense err")))
				return
			}
		}

		response.Ok(w)
	}
}
