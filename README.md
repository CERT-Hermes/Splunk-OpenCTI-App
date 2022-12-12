**Current version of Pycti**: 5.4.1 (the library must be equal to your OpenCTI instance!)

# TODO
  - [ ] Create a setup page to configure the application
  - [ ] Create a custom command to query the GraphQL and create alerts monitoring

# Installation steps

## OpenCTI Platform

1. Create a new user with the builtin `Connector` role.
2. Keep its API token next to you

## Splunk

1. Install the App in your Search Head only
2. Restart the Search Head
3. Make these requests API call with a Splunk valid account that have write capability for this app:

**Add the OpenCTI endpoint URL**

```sh
curl -sku admin:fixme -d url=https://opencti:8080 https://your-search-head-url:8089/servicesNS/nobody/opencti/configs/conf-opencti/opencti
```

**Add your organization name that appear in OpenCTI**

```sh
curl -sku admin:fixme -d organization_name="MY ORGANIZATION" https://localhost:8089/servicesNS/nobody/opencti/configs/conf-opencti/connector
```

**Add the API token of the newly created account in OpenCTI (step 1.2)**

```sh
curl -sku admin:fixme -d password=FIXME -d name=token -d realm=opencti https://localhost:8089/servicesNS/nobody/opencti/storage/passwords`
```


# Send your first Observed Data

1. The name of your saved search must be started by "CTI000-", the name will appear in the work queues in OpenCTI.
2. List of fields that are mandatory in the output of your search:
    - STIX2 Datatype field (see below for the complete list)
    - count ; must be a number
    - first_seen ; must be a timestamp
    - last_seen ; must be a timestamp

Example:

```
index=firewall sourcetype=threat domain=* NOT(dest IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)) NOT(domain IN (*.office.com, *.doubleclick.net))
| stats min(_time) as first_seen max(_time) as last_seen count by domain 
| rename domain as Domain-Name.value 
| datavalidator domain:Domain-Name.value
```

Output:

| Domain-Name.value | first_seen | last_seen  | count |
| ----------------- | ---------- | ---------- | ----: |
| google.com        | 1642001850 | 1642001850 | 110   |

This search returns all public/external domains that users browse.

The `| datavalidator` is embedded in this app and it is based on "validators" python library. You could also use the Splunk URL ToolBox  App to filter the domain based on the TLD.

You cannot add multiple STIX2 fields in the same time, only the first occurrence will be taken.

# List of supported STIX2 Datatype:

- Domain-Name.value
- File.hashes.MD5
- File.hashes.SHA-1
- File.hashes.SHA-256
- File.name
- IPv4-Addr.value
- IPv6-Addr.value
- Email-Addr.value

# DEBUG Steps

This app generate JSON logs info and debug that you could find here : 

```
index=_internal source=*alert_opencti_importer.log
```

To change the verbosity, use this API call:

```sh
curl -sku admin:fixme -d log_level=DEBUG https://your-search-head-url:8089/servicesNS/nobody/opencti/configs/conf-opencti/connector
```

Or, edit the etc/local/opencti.conf file and this configuration:

```ini
[connector]
log_level = DEBUG
```

The restart of your SH isn't required. The action is called every time that the search ran.


# DEV: if you need to update dependencies:

```
pip install --target bin/lib --no-deps --upgrade pycti stix2~=2.1.0 simplejson stix2-patterns antlr4-python3-runtime python-magic~=0.4.24 python_json_logger~=2.0.2 datefinder~=0.7 pika~=1.2 sseclient~=0.0.27 prometheus-client~=0.11.0 validators
```

See requirements.txt of pycti library.
