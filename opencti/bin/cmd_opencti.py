# coding: utf-8

from pathlib import Path
import requests
import sys
import json

home = Path(__file__).resolve().parent
sys.path.insert(0, (home / "lib").as_posix())

from splunklib.searchcommands import (
    dispatch, 
    GeneratingCommand, 
    Configuration, 
    Option
)

GET_CONNECTORS_STATE_QUERY = """
query GetConnectors {
  connectors {
    id
    name
    active
    connector_type
    works {
      timestamp
    }
  }
}
"""

def copy_conf_from_splunk(d: dict) -> dict:
    """
    Splunk returns its default keys that are useless
    for OpenCTI platform.
    """
    return {
        k: v for k, v in d.items() if not k in ["disabled"] and not k.startswith("eai:")
    }

@Configuration(type='reporting')
class opencti(GeneratingCommand):
    def generate(self):
        if not self.fieldnames:
            self.write_error("No query name given.")
            return

        config = dict(
            map(
                lambda stanza: (stanza.name, copy_conf_from_splunk(stanza.content)),
                self.service.confs["opencti"]
            )
        )
        config["opencti"]["url"] = config["opencti"]["url"].rstrip("/") + "/graphql"

        token = dict(
            (x.name, x.clear_password)
            for x in self.service.storage_passwords
            if x.realm == "opencti"
        ).get("opencti:token:")

        if not token:
            self.write_error("The connector token is missing. Exiting.")
            exit(-1)
        config["opencti"]["token"] = token

        s = requests.Session()
        s.verify = False
        s.headers.update({
            "Authorization": f"Bearer {config['opencti']['token']}",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })



        if self.fieldnames[0] == "connectors_state":
            r = s.post(config["opencti"]["url"], data=json.dumps(
                {
                    "query": GET_CONNECTORS_STATE_QUERY
                }
            ))

            r.raise_for_status()

            data = r.json()
            for connector in data["data"]["connectors"]:
                timestamp_last_work = next(iter(connector["works"]), "null")
                if isinstance(timestamp_last_work, dict):
                    timestamp_last_work = timestamp_last_work["timestamp"]
                
                yield {
                    "name": connector["name"],
                    "id": connector["id"],
                    "active": connector["active"],
                    "connector_type": connector["connector_type"],
                    "timestamp_last_work": timestamp_last_work,
                }

        else:
            self.write_error("Unknown query.")
            return

dispatch(opencti, sys.argv, sys.stdin, sys.stdout, __name__)
