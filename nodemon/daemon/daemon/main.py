"""The Vegeta Daemon main program
"""
import logging
import os
import socket
import threading
import time

import click
from etcd3 import Client

from .gracefulkiller import GracefulKiller, GracefulKillerDone

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger("vegeta-daemon")

ETCD_KEY_DAEMON_HEARTBEAT = "/agents/{}/pods/{}/heartbeat"
HEARTBEAT_INTERVAL = 15


@click.command()
@click.option(
    "--etcd-host",
    type=str,
    default=os.getenv("ETCD_CLUSTER_HOST", "localhost"),
    required=True,
    help="to specify the etcd cluster host",
)
@click.option(
    "--etcd-port",
    type=int,
    default=os.getenv("ETCD_CLUSTER_PORT", "2379"),
    required=True,
    help="to specify the etcd cluster port",
)
@click.option(
    "--agent-id",
    type=str,
    default=os.getenv("AGENT_ID", "agentID"),
    required=True,
    help="to specify the agent ID",
)
def main(etcd_host, etcd_port, agent_id):
    killer = GracefulKiller(1)

    # setting up the etcd
    etcd_client = Client(host=etcd_host, port=int(etcd_port))

    # Heartbeat to etcd, key: ETCD_KEY_DAEMON_HEARTBEAT
    start = int(time.time())

    def heartbeat():
        key = ETCD_KEY_DAEMON_HEARTBEAT.format(agent_id, socket.gethostname())
        while True:
            etcd_client.put(key, {"start": start, "update": int(time.time())})
            time.sleep(HEARTBEAT_INTERVAL)

    heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
    heartbeat_thread.start()
    LOGGER.info("Started heartbeat thread")

    try:
        killer.sleep()
    except GracefulKillerDone:
        pass
