# coding: utf-8

from pathlib import Path
import sys

home = Path(__file__).resolve().parent
sys.path.insert(0, (home / "lib").as_posix())

import validators
from splunklib.searchcommands import dispatch, EventingCommand, Configuration

FIELDS_VALIDATOR = {
    "md5": validators.md5,
    "sha1": validators.sha1,
    "sha256": validators.sha256,
    "domain": validators.domain,
    "ipv4": validators.ipv4,
    "ipv6": validators.ipv6,
    "email": validators.email,
    "url": validators.url,
}


@Configuration()
class datavalidator(EventingCommand):
    def transform(self, records):
        if len(self.fieldnames) > 0:

            args = dict(
                map(
                    lambda x: (x[1], x[0]),
                    [
                        arg.split(":")
                        for arg in self.fieldnames
                        if arg.split(":")[0] in FIELDS_VALIDATOR
                    ],
                )
            )

            if not args:
                raise RuntimeError("You must specify a valid field type.")

            is_filtered = False
            for record in records:

                for _field, _type in args.items():
                    if not FIELDS_VALIDATOR[_type](record.get(_field, "")):
                        is_filtered = True
                        break

                if is_filtered:
                    is_filtered = False
                    continue

                yield record

        else:
            raise RuntimeError("You must specify positional arguments.")


dispatch(datavalidator, sys.argv, sys.stdin, sys.stdout, __name__)
