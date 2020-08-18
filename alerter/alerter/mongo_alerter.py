# -*- coding: utf-8 -*-
"""A custom Alerter to send the alerts to Mongo
"""
import logging

from elastalert.util import EAException
from elastalert.alerts import Alerter, BasicMatchString
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from staticconf.loader import yaml_loader

from .main import ELASTALERT_CONFIG_YAML


def db_login():
    """parse the yaml, get the mongo configuration and return a MongoClient"""
    try:
        alerter_options = yaml_loader(ELASTALERT_CONFIG_YAML)["alerter_options"]
        host = alerter_options["mongo_host"]
        port = alerter_options["mongo_port"]
        username = alerter_options["mongo_username"]
        password = alerter_options["mongo_password"]
        return MongoClient(host=host, port=port, username=username, password=password)
    except FileNotFoundError:
        raise EAException("{} is not found".format(ELASTALERT_CONFIG_YAML))
    except KeyError as ex:
        raise EAException("{}: key is not found".format(ex))
    except ConnectionFailure as ex:
        raise EAException("error connecting to Mongodb: {}".format(ex))


class MongoAlerter(Alerter):
    """Sends alerts to Mongo
    """

    def __init__(self, rule):
        super(MongoAlerter, self).__init__(rule)
        self.client = db_login()
        self.inserted_id = ""

    def alert(self, matches):
        """Alert is called

        Arguments:
            matches {[type]} -- Matches is a list of match dictionaries.
                                It contains more than one match when the alert has
                                the aggregation option set.
        """
        for match in matches:
            match_string = str(BasicMatchString(self.rule, match))
            logging.info(match_string)

        body = self.create_alert_body(matches)

        mongo_col = self.client["elasticalert"]["alert"]
        mongo_dict = {"raw_data": body}
        in_data = mongo_col.insert_one(mongo_dict)
        self.inserted_id = in_data.inserted_id

    def get_info(self):
        """get_info is called after an alert is sent to get data that is written back
           to Elasticsearch in the field "alert_info".

           It should return a dict of information relevant to what the alert does.

        Returns:
            [dict] -- a dictionary of information
        """
        return {"type": "Mongo Alerter", "inserted_id": str(self.inserted_id)}
