#!/usr/bin/env python3
import json
import pathlib
import sys

import jsonschema


def validate(schema_path: pathlib.Path, instance_path: pathlib.Path) -> None:
    with schema_path.open(encoding="utf-8") as schema_file:
        schema = json.load(schema_file)
    with instance_path.open(encoding="utf-8") as instance_file:
        instance = json.load(instance_file)
    jsonschema.validate(instance, schema)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: validate-schemas.py TRACE EVIDENCE", file=sys.stderr)
        return 2
    validate(pathlib.Path("schemas/echorv.trace.v1.schema.json"), pathlib.Path(sys.argv[1]))
    validate(
        pathlib.Path("schemas/echorv.evidence.v1.schema.json"),
        pathlib.Path(sys.argv[2]),
    )
    print("EchoRV trace and evidence schemas: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
