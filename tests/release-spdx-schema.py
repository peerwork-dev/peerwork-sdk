"""Offline formal validation against the byte-pinned official SPDX2.3 schema."""
import argparse
import hashlib
import json
from pathlib import Path
from jsonschema import Draft7Validator
from referencing import Registry

SCHEMA_SHA='239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b'
SCHEMA_URL='https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json'

def no_external_references(uri):raise RuntimeError('external schema retrieval forbidden')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--schema',type=Path,required=True);parser.add_argument('--document',type=Path,required=True);parser.add_argument('--preserved-exploratory',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();encoded=args.schema.read_bytes()
    assert hashlib.sha256(encoded).hexdigest()==SCHEMA_SHA,'official SPDX schema bytes changed'
    schema=json.loads(encoded);Draft7Validator.check_schema(schema)
    validator=Draft7Validator(schema,registry=Registry(retrieve=no_external_references))
    original=None
    if args.preserved_exploratory:
        errors=list(validator.iter_errors(json.loads(args.preserved_exploratory.read_text())))
        assert errors and any('documentComment' in error.message for error in errors),'exploratory field failure did not reproduce'
        original='REJECTED retrospectively; not an original-run schema result'
    final=json.loads(args.document.read_text());assert not list(validator.iter_errors(final)),'frozen SPDX document violates official schema'
    result=dict(schema_url=SCHEMA_URL,schema_sha256=SCHEMA_SHA,validator='jsonschema4.25.1 Draft7',schema_id=schema['$id'],original_exploratory_output=original,final_frozen_output='PASS',final_packages=len(final['packages']),external_reference_fetches=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
