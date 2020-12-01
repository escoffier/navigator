package repository

import (
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"go.mongodb.org/mongo-driver/mongo"
)

func MongoSessionCommitter(sessionContext mongo.SessionContext, err *error) func() {
	return func() {
		if *err != nil {
			transactionErr := sessionContext.AbortTransaction(sessionContext)
			if transactionErr != nil {
				logging.GetLogger().Error().Err(*err).Msg("Failed to abort transaction. DB may be in inconsistent state")
			} else {
				logging.GetLogger().Error().Err(*err).Msg("Mongo transaction aborted")
			}
		} else {
			transactionErr := sessionContext.CommitTransaction(sessionContext)
			if transactionErr != nil {
				logging.GetLogger().Error().Err(*err).Msg("Failed to commit transaction. DB may be in inconsistent state")
			} else {
				logging.GetLogger().Info().Msg("Mongo transaction successfully committed")
			}
		}
	}
}
