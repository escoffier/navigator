# -*- coding: utf-8 -*-
"""The Vegeta Alerter main program
"""
import argparse
import logging
import os
import shutil
import threading

from elastalert.elastalert import ElastAlerter
from etcd3 import Client

from .gracefulkiller import GracefulKiller, GracefulKillerDone

LOGGER = logging.getLogger("vegeta-alerter")
LOGGER.setLevel(logging.INFO)

# The key for alerter config.yaml
ETCD_KEY_ALERTER_CONFIG_YAML = "/alerter/config.yaml"
ETCD_KEY_ALERTER_RULES_YAML_PREFIX = "/alerter/rules/"

ELASTALERT_CONFIG_YAML = "/tmp/elastalert/config.yaml"
ELASTALERT_RULES_FOLDER = "/tmp/elastalert/rules"


class ElastAlerterThread(threading.Thread):
    """A thread for running the ElastAlerter
    """

    def __init__(self, group=None, target=None, name=None):
        super(ElastAlerterThread, self).__init__(group=group, target=target, name=name)
        self.elastalerter = None

    def run(self):
        LOGGER.info("ElastAlerterThread started")
        self.elastalerter = ElastAlerter(
            ["--config", ELASTALERT_CONFIG_YAML, "--verbose", "--es_debug"]
        )
        self.elastalerter.start()
        LOGGER.info("ElastAlerterThread stopped")

    def stop(self):
        LOGGER.info("Stopping ElastAlerterThread")
        if self.elastalerter:
            self.elastalerter.stop()


def update_file(file_path, content):
    """update the file at the file_path with the content
    by first writing to a file.tmp and rename it

    If content is None, then this function will remove the file.

    Arguments:
        file_path {string} -- the path of the file
        content {bytes} -- the content of the file
    """
    tmp_file = "{}.tmp".format(file_path)
    if content:
        with open(tmp_file, "wb") as f:
            f.write(content)
        shutil.move(tmp_file, file_path)
    else:
        # delete the file
        try:
            os.remove(file_path)
        except OSError:
            pass


def main():
    """main function
    """
    killer = GracefulKiller(1)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--etcd-host",
        help="to specify the etcd cluster host",
        action="store",
        dest="etcd_host",
        default=os.getenv("ETCD_CLUSTER_HOST", "localhost"),
    )
    parser.add_argument(
        "--etcd-port",
        help="to specify the etcd cluster port",
        action="store",
        dest="etcd_port",
        default=os.getenv("ETCD_CLUSTER_PORT", "2379"),
    )
    args = parser.parse_args()

    # mkdir -p the folders
    try:
        os.makedirs(os.path.dirname(ELASTALERT_CONFIG_YAML))
    except FileExistsError:
        pass
    try:
        os.makedirs(ELASTALERT_RULES_FOLDER)
    except FileExistsError:
        pass

    # initialize an etcd client
    etcd_client = Client(host=args.etcd_host, port=int(args.etcd_port))

    # a lock to protect the state of the ElastAlert with the watchers
    lock = threading.Lock()

    # delete all the existing rules if any
    LOGGER.info("deleting the existing rules in the filesystem")
    for the_file in os.listdir(ELASTALERT_RULES_FOLDER):
        file_path = os.path.join(ELASTALERT_RULES_FOLDER, the_file)
        if os.path.isfile(file_path):
            os.unlink(file_path)

    # fetch all the rules first
    LOGGER.info("fetching the current rules from etcd")
    for kv in etcd_client.range(ETCD_KEY_ALERTER_RULES_YAML_PREFIX, prefix=True).kvs or []:
        filename = kv.key.decode("utf-8").replace(ETCD_KEY_ALERTER_RULES_YAML_PREFIX, "")
        LOGGER.info("fetched %s", filename)
        file_path = "{}/{}".format(ELASTALERT_RULES_FOLDER, filename)
        update_file(file_path, kv.value)

    # an ElastAlerter thread
    elastalerter_thread = ElastAlerterThread()

    # sync GET the config.yaml to spin up the ElastAlerter
    LOGGER.info("fetching the config.yaml from etcd")
    config_yamls_kvs = etcd_client.range(ETCD_KEY_ALERTER_CONFIG_YAML).kvs
    if config_yamls_kvs:
        config_yaml = config_yamls_kvs[0].value
        if config_yaml:
            update_file(ELASTALERT_CONFIG_YAML, config_yaml)

            # start the ElastAlerterThread
            LOGGER.info("fetched config.yaml and start ElastAlerter")
            lock.acquire()
            try:
                elastalerter_thread.start()
            finally:
                lock.release()

    # setup watch for rules
    wr = etcd_client.Watcher(
        key=ETCD_KEY_ALERTER_RULES_YAML_PREFIX, prefix=True, progress_notify=True, prev_kv=True,
    )

    def on_wr_event(e):
        nonlocal lock
        filename = e.key.decode("utf-8").replace(ETCD_KEY_ALERTER_RULES_YAML_PREFIX, "")
        file_path = "{}/{}".format(ELASTALERT_RULES_FOLDER, filename)
        lock.acquire()
        try:
            update_file(file_path, e.value)
        finally:
            lock.release()
        LOGGER.info("updated rules yaml: %s", filename)

    wr.onEvent(on_wr_event)
    wr.runDaemon()
    LOGGER.info("started etcd watcher for rules")

    # setup watch for config.yaml changes
    wc = etcd_client.Watcher(
        key=ETCD_KEY_ALERTER_CONFIG_YAML, progress_notify=True, prev_kv=True, no_delete=True,
    )

    def on_wc_event(e):
        """On config.yaml change event, restart the elastalerter thread

        Arguments:
            e -- etcd watch event
        """
        LOGGER.info("received config.yaml update notification")
        nonlocal lock
        nonlocal elastalerter_thread
        lock.acquire()
        try:
            if elastalerter_thread and elastalerter_thread.isAlive():
                elastalerter_thread.stop()
                elastalerter_thread.join()
            update_file(ELASTALERT_CONFIG_YAML, e.value)
            elastalerter_thread = ElastAlerterThread()
            elastalerter_thread.start()
        finally:
            lock.release()

    wc.onEvent(on_wc_event)
    wc.runDaemon()
    LOGGER.info("started etcd watcher for config.yaml")

    try:
        killer.sleep(None)
    except GracefulKillerDone:
        pass
    finally:
        LOGGER.info("stopping all etcd watcher")
        wr.stop()
        wc.stop()

        LOGGER.info("stopping the ElastAlerter thread")
        if elastalerter_thread and elastalerter_thread.isAlive():
            elastalerter_thread.stop()
            elastalerter_thread.join()

    LOGGER.info("program exits")
