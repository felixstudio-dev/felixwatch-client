"""Offline draft consumer review. No FAC adapter, network, secret or authority."""
import json
import re

from handoff_snapshot import verify_for_review
from preflight_client import strict_object, validate_config

DRAFT_SCHEMA = 'WATCH_CONSUMER_REVIEW_DRAFT_1'
FIELDS = {'schema', 'environment', 'issuer', 'audience', 'scope', 'request_id',
          'credential_id', 'credential_version', 'credential_kind', 'status',
          'issued_at', 'expires_at', 'customer_id', 'agent_id', 'infrastructure_id',
          'server_id', 'site_ids', 'service_ids', 'package_sha256', 'config_sha256',
          'heartbeat_delivery'}
EXPECTATIONS = {'environment', 'issuer', 'audience', 'required_scope', 'request_id', 'now'}


class ProvisioningRejected(Exception):
    pass


def _identifier(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', value):
        raise ValueError()


def _integer(value):
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError()


def _identifiers(value):
    if type(value) is not list or len(value) > 256:
        raise ValueError()
    for item in value:
        _identifier(item)
    if len(set(value)) != len(value):
        raise ValueError()


def review(snapshot, envelope_bytes, expectation):
    """Compare untrusted draft metadata to local expectations; always HELD.

    Expected scope/time/issuer are fixture inputs, NOT authenticated server
    assertions. A future admitted adapter must establish that trust separately.
    Plaintext service and HMAC secrets are deliberately absent from this schema.
    """
    try:
        if type(envelope_bytes) is not bytes or len(envelope_bytes) > 16384:
            raise ValueError()
        if type(expectation) is not dict or set(expectation) != EXPECTATIONS:
            raise ValueError()
        for key in EXPECTATIONS - {'now'}:
            _identifier(expectation[key])
        _integer(expectation['now'])
        if expectation['environment'] not in ('Live', 'Test'):
            raise ValueError()
        envelope = json.loads(envelope_bytes, object_pairs_hook=strict_object)
        if type(envelope) is not dict or set(envelope) != FIELDS:
            raise ValueError()
        for key in FIELDS - {'scope', 'site_ids', 'service_ids', 'issued_at', 'expires_at', 'credential_version'}:
            _identifier(envelope[key])
        for key in ('scope', 'site_ids', 'service_ids'):
            _identifiers(envelope[key])
        for key in ('issued_at', 'expires_at', 'credential_version'):
            _integer(envelope[key])
        if (envelope['schema'] != DRAFT_SCHEMA or envelope['status'] != 'active' or
                envelope['credential_kind'] != 'service_access' or
                envelope['heartbeat_delivery'] != 'SEPARATE_CUSTODY_REQUIRED' or
                envelope['credential_version'] < 1 or
                not envelope['issued_at'] <= expectation['now'] < envelope['expires_at']):
            raise ValueError()
        for key in ('environment', 'issuer', 'audience', 'request_id'):
            if envelope[key] != expectation[key]:
                raise ValueError()
        if envelope['scope'] != [expectation['required_scope']]:
            raise ValueError()
        verified = verify_for_review(snapshot)
        config = validate_config(snapshot.config)
        for key in ('package_sha256', 'config_sha256'):
            if envelope[key] != verified[key]:
                raise ValueError()
        for key in ('customer_id', 'agent_id', 'infrastructure_id', 'server_id'):
            if envelope[key] != config[key]:
                raise ValueError()
        for field, section, identity in (('site_ids', 'sites', 'site_id'), ('service_ids', 'services', 'service_id')):
            configured = [item[identity] for item in config[section]]
            _identifiers(configured)
            if set(envelope[field]) != set(configured):
                raise ValueError()
    except Exception:
        # Never expose JSON/parser/config exception data or caller-owned metadata.
        raise ProvisioningRejected('PROVISIONING_DRAFT_REJECTED') from None
    return {'review': 'COMPATIBLE_DRAFT_NOT_AUTHENTICATED', 'integration': 'HELD',
            'installation': 'HELD', 'activation': 'HELD'}
