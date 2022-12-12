# coding: utf-8

# Built-in lib
from pathlib import Path
from datetime import datetime

import os
import sys
import time
import json
import logging

home = Path(__file__).resolve().parent
splunk_home = Path(os.environ.get("SPLUNK_HOME", "/opt/splunk")).resolve()
sys.path.insert(0, (home / "lib").as_posix())

# Custom lib
import stix2

from pycti import OpenCTIConnectorHelper, Identity, ObservedData
from stix2 import (
    DomainName,
    EmailAddress,
    File,
    IPv4Address,
    IPv6Address,
)
from pythonjsonlogger import jsonlogger

import splunklib.client as client
import splunklib.results as results

# https://docs.splunk.com/Documentation/Splunk/latest/Admin/Limitsconf#.5Bsearchresults.5D
MAX_RESULT_ROWS = 50000

supported_observable_type = [
    "Domain-Name.value",
    "File.hashes.MD5",
    "File.hashes.SHA-1",
    "File.hashes.SHA-256",
    "File.name",
    "IPv4-Addr.value",
    "IPv6-Addr.value",
    "Email-Addr.value",
]

class CustomAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        # merge adapter global extra with local extra
        if "extra" in kwargs:
            kwargs["extra"].update(self.extra)
            return msg, kwargs
        return msg, kwargs


def setup_logger(logger_name):
    logger = logging.getLogger(logger_name)
    logger.propagate = False

    log_file = splunk_home / f"var/log/splunk/{logger_name}.log"

    log_handler = logging.FileHandler(log_file)
    log_handler.setFormatter(
        jsonlogger.JsonFormatter(
            """
        %(timestamp)s %(levelname)s %(name)s %(message)s""",
            timestamp=True,
            rename_fields={
                "levelname": "log_level",
                "name": "log_name",
            },
        )
    )
    logger.handlers = [log_handler]
    logger.setLevel(logging.INFO)

    return logger


def is_public_ip(ip):
    if len(ip) > 16:
        return False
    ip = list(map(int, ip.strip().split(".")[:2]))
    if ip[0] == 0:
        return False
    if ip[0] == 127:
        return False
    if ip[0] == 10:
        return False
    if ip[0] == 172 and ip[1] in range(16, 32):
        return False
    if ip[0] == 192 and ip[1] == 168:
        return False
    return True

def build_stix_bundle(logger, config, results):
    # Built-in organization
    organization = stix2.Identity(
        id=Identity.generate_id(config["connector"]["organization_name"], "system"),
        name=config["connector"]["organization_name"],
        identity_class="system",
    )
    # Objects
    bundle_objects = [organization]

    labels = config["observable"]["labels"]

    for observable in results:

        key = next(filter(lambda x: x in supported_observable_type, observable))

        if key.startswith("IPv") and not is_public_ip(observable[key]):
            continue

        # Observable
        stix_observable = None
        custom_properties = {
            "x_opencti_score": 0,
            "labels": labels,
            "created_by_ref": organization["id"],
        }
        if key == "Domain-Name.value":
            stix_observable = DomainName(
                value=observable[key],
                object_marking_refs=[stix2.TLP_GREEN],
                custom_properties=custom_properties,
            )
        elif key == "File.hashes.MD5":
            stix_observable = File(
                hashes={"MD5": observable[key]},
                object_marking_refs=[stix2.TLP_GREEN],
                custom_properties=custom_properties,
            )
        elif key == "File.hashes.SHA-1":
            stix_observable = File(
                hashes={"SHA-1": observable[key]},
                object_marking_refs=[stix2.TLP_GREEN],
                custom_properties=custom_properties,
            )
        elif key == "File.hashes.SHA-256":
            stix_observable = File(
                hashes={"SHA-256": observable[key]},
                object_marking_refs=[stix2.TLP_GREEN],
                custom_properties=custom_properties,
            )
        elif key == "File.hashes.name":
            stix_observable = File(
                name=observable[key],
                object_marking_refs=[stix2.TLP_GREEN],
                custom_properties=custom_properties,
            )
        elif key == "IPv4-Addr.value":
            stix_observable = IPv4Address(
                value=observable[key],
                object_marking_refs=[stix2.TLP_GREEN],
                custom_properties=custom_properties,
            )
        elif key == "IPv6-Addr.value":
            stix_observable = IPv6Address(
                value=observable[key],
                object_marking_refs=[stix2.TLP_GREEN],
                custom_properties=custom_properties,
            )
        elif key == "Email-Addr.value":
            stix_observable = EmailAddress(
                value=observable[key],
                object_marking_refs=[stix2.TLP_GREEN],
                custom_properties=custom_properties,
            )
        if stix_observable is not None:
            bundle_objects.append(stix_observable)
            # Observed Data
            first_observed = datetime.fromtimestamp(
                round(float(observable["first_seen"]))
            )
            last_observed = datetime.fromtimestamp(
                round(float(observable["last_seen"]))
            )
            stix_observed_data = stix2.ObservedData(
                id=ObservedData.generate_id([stix_observable["id"]]),
                number_observed=int(observable["count"]),
                first_observed=first_observed,
                last_observed=last_observed,
                object_refs=[stix_observable],
                created_by_ref=organization["id"],
                labels=labels,
                object_marking_refs=[stix2.TLP_GREEN],
            )
            bundle_objects.append(stix_observed_data)

    number_of_bundles = len(bundle_objects)
    if number_of_bundles > 1:
        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
        logger.info("bundles processed", extra={"number_of_bundles": number_of_bundles})
        logger.debug("serialized bundle", extra={"bundle": bundle})
        return bundle
    else:
        return None


def copy_conf_from_splunk(d: dict) -> dict:
    """
    Splunk returns its default keys that are useless
    for OpenCTI platform.
    """
    return {
        k: v for k, v in d.items() if not k in ["disabled"] and not k.startswith("eai:")
    }


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        payload = json.loads(sys.stdin.read())

        # splunk job variables
        session_key = payload.get("session_key")
        search_name = payload.get("search_name")
        alert_options = payload.get("configuration")
        job_id = payload.get("sid")
        for_each_results = payload.get("result_id", False)

        search_id = search_name.split("-")[0]

        logger = setup_logger("alert_opencti_importer")
        logger = CustomAdapter(
            logger, extra={"search_name": search_name, "sid": job_id}
        )

        service = client.connect(token=session_key, owner="nobody", app="opencti")

        config = dict(
            map(
                lambda stanza: (stanza.name, copy_conf_from_splunk(stanza.content)),
                service.confs["opencti"]
            )
        )
        config["opencti"]["url"] = config["opencti"]["url"].rstrip("/")
        config["observable"]["labels"] = config["observable"]["labels"].replace(" ", "").split(",")

        # Merge global labels with search local labels
        alert_labels = alert_options.get("labels")
        if alert_labels:
            alert_labels = set(alert_labels.replace(" ", "").split(","))
            labels = set(config["observable"]["labels"]) | alert_labels
            config["observable"]["labels"] = list(labels)

        # considering debugging the connector, debug in the same time
        # this alert script.
        logger.setLevel(config["connector"]["log_level"])

        token = dict(
            (x.name, x.clear_password)
            for x in service.storage_passwords
            if x.realm == "opencti"
        ).get("opencti:token:")

        if not token:
            logger.error(f"The connector token is missing. Exiting.")
            exit(-1)
        config["opencti"]["token"] = token

        # In Splunk, there are two methods of triggering alerts:
        #   - "For Each Results": the action will be played for each row of the results table
        #   - "Once": the action will be played only once for all results.
        #       Except that, only the first result will be returned in this script not all.
        #       It is necessary to retrieve the job details manually.
        # No matter which option is chosen, we will return always a list of dict.
        if for_each_results:
            job_result_count = 1
            results = [payload["result"]]
            fields = list(payload["result"])
        else:
            job = service.job(job_id)
            job_result_count = int(job.content["resultCount"])
            fields = {}

            results = list(
                map(
                    lambda row : (dict(row), fields.update(dict.fromkeys(row)))[0],
                    [ row for offset in range(0, job_result_count, MAX_RESULT_ROWS)
                        for row in results.ResultsReader(job.results(count=0, offset=offset))
                    ]
                )
            )

            if job_result_count > MAX_RESULT_ROWS:       
                logger.warning(f"The job has returned lot of results that could cause performance issue. If not impact noticed, you can ignore this warning.", 
                    extra = {
                        "job_result_count": job_result_count
                    }
                )

            fields = list(fields)

        # convert str to list when carriage return is present
        list(
            map(
                lambda d: next(d.__setitem__(k, (v.split("\n") 
                        if isinstance(v, str) and "\n" in v else v)) 
                    for k,v in d.items()), results
                ) 
            )

        # TODO: vérifier que les champs "first_seen, last_seen et count" soient
        #       également présent
        if not any(filter(lambda field: field in supported_observable_type, fields)):
            # bypass search validation?
            logger.error("There is no observable type as field. Exiting.")
            exit(-1)

        logger.debug(
            f"Splunk job details",
            extra={
                "job_result_count": job_result_count,
                "results_processed": len(results),
            },
        )

        try:
            # Send result to OpenCTI
            helper = OpenCTIConnectorHelper(config)

            # Initiate work
            friendly_name = f"{search_id} run @ " + time.strftime("%Y-%m-%d %H:%M:%S")
            work_id = helper.api.work.initiate_work(helper.connect_id, friendly_name)

            # Build STIX bundle from the data
            bundle = build_stix_bundle(logger, config, results)
            if bundle:
                # Send STIX bundle
                helper.log_info("Sending event STIX2 bundle")
                helper.send_stix2_bundle(bundle, work_id=work_id, update=True)
            else:
                logger.debug("No bundle to send")

        except Exception as e:
            helper.log_error(str(e))
            logger.error(e, exc_info=True)
            exit(-1)
