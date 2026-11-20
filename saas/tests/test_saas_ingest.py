import os
import json
import pytest
from saas.ingest.main import app

# Load valid sample payload from contracts/samples
SAMPLE_PAYLOAD_PATH = os.path.join(
    os.path.dirname(__file__), "../../contracts/samples/valid_payload_1.json"
)

with open(SAMPLE_PAYLOAD_PATH, "r", encoding="utf-8") as f:
    SAMPLE_VALID_PAYLOAD = json.load(f)


def test_schema_validates_sample():
    import jsonschema
    from saas.ingest.main import load_schema
    schema = load_schema()
    # Validate against frozen wire schema
    jsonschema.validate(instance=SAMPLE_VALID_PAYLOAD, schema=schema)


def test_reject_payload_with_free_text_field():
    import jsonschema
    from saas.ingest.main import load_schema
    schema = load_schema()
    invalid_payload = dict(SAMPLE_VALID_PAYLOAD)
    invalid_payload["raw_log"] = "SELECT * FROM users WHERE password='supersecret'"

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=invalid_payload, schema=schema)


def test_reject_payload_with_missing_field():
    import jsonschema
    from saas.ingest.main import load_schema
    schema = load_schema()
    invalid_payload = dict(SAMPLE_VALID_PAYLOAD)
    del invalid_payload["signature"]

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=invalid_payload, schema=schema)
