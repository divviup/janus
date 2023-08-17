# Taskprov Extension

Janus has limited support for the Taskprov extension, as defined in
[draft-wang-ppm-dap-taskprov][1]. We support it largely to facilitiate
integrations with Divvi Up partners who have requested support for the extension.

Taskprov defines a mechanism for provisioning tasks into a DAP aggregator. Task
configuration is performed in-band as clients submit reports. Clients will submit
reports containing the task configuration, and the aggregator will respond by
validating and provisioning the task. The exact mechanism of how the task
configuration is provided depends on the version of the implemented spec draft.

[1]: https://datatracker.ietf.org/doc/draft-wang-ppm-dap-taskprov/

## Compatibility

See this table for the matrix of branches to Taskprov versions. Taskprov is not
implemented on any branches missing from this list.

| Git branch | Taskprov draft version | Conforms to protocol? | Status |
| ---------- | ------------- | --------------------- | ------ |
| `release/0.subscriber-01` | [`draft-wang-ppm-dap-taskprov-04`][2] | Helper only | [Supported][3] |
| `release/0.5` | [`draft-wang-ppm-dap-taskprov-04`][2] | Helper only | Supported |
| `main` | [`draft-wang-ppm-dap-taskprov-04`][2] | Helper only | Supported |

[2]: https://datatracker.ietf.org/doc/draft-wang-ppm-dap-taskprov/04/
[3]: https://github.com/divviup/janus/pull/1742

## Operational Considerations

Our implementation of Taskprov defines two new database entities that aren't
otherwise used in Janus.

- Global HPKE Keypair: A non-task-specific HPKE configuration advertised on
  `/hpke_config` which is used by Taskprov clients to encrypt their reports.
- Peer Aggregator: Another aggregator operated by a partner organization that
  supports the Taskprov extension.

Once these entities are present in the database, we can enable Taskprov in
the aggregator configuration like so:
```yaml
taskprov_config:
  enabled: true
```

Once this flag is enabled, it must not be disabled. You cannot go from a Taskprov
aggregator back to a non-Taskprov aggregator.

### Peer Aggregators

Peer aggregators are identified by their HTTP endpoint (as shared in task
advertisement) and their role relative to our aggregator. For instance, if we
operate a helper, then the peer aggregator should be a leader.

It is possible for multiple peer aggregators to be configured, and for the the
same peer endpoint to be configured in both Leader and Helper roles (although
take note of Janus support for operating as a Leader).

#### Shared Secrets and Parameters

We must agree upon and share the following parameters with peer aggregators 
out-of-band:

Sensitive values:
- `verify_key_init`: A random 32-byte string used for deriving task-specific VDAF
  verify keys.
- `aggregator_auth_tokens`: A list of bearer tokens used by leader peer aggregator
  to authenticate to a helper peer aggregator.
- `collector_auth_tokens`: Unused in Janus, since it cannot operate as a Taskprov
  leader.

Non-sensitive values:
- `collector_hpke_config`: The single HPKE configuration of a collector that
  aggregate shares will be encrypted to. This key belongs to whoever will be
  collecting on taskprov tasks.
- `tolerable_clock_skew`: This isn't used in Janus since it can't operate as a
  Taskprov leader, but is still required for task definitions. It can be set to
  something arbitrary--the peer does not need to agree upon this value.
- `report_expiry_age`: How long in seconds to persist client reports. Omit to
  set no report expiration.

#### Provisioning

Peer aggregators are configured by system operators through the Janus aggregator
API.

Example for creating a new peer aggregator in the Leader role:
```bash
AGGREGATOR_URL=http://localhost:8081
AGGREGATOR_API_TOKEN="BASE64URL UNPADDED TOKEN HERE"

# Generate shared parameters. Share these with the peer, or ask for the values
# that they have derived. Notice that these values are base64url encoded with
# no padding.
VERIFY_KEY_INIT=$(openssl rand 32 | basenc -w0 --base64url | sed 's/=//g')
AGGREGATOR_AUTH_TOKEN=$(echo "some_helpful_identifier_$(openssl rand -hex 32)" | 
    basenc -w0 --base64url | sed 's/=//g')

curl -v \
    -H "Authorization: Bearer $AGGREGATOR_API_TOKEN" \
    -H "Accept: application/vnd.janus.aggregator+json;version=0.1" \
    -H "Content-Type: application/vnd.janus.aggregator+json;version=0.1" \
    "$AGGREGATOR_URL/taskprov/peer_aggregators" \
    --data "{
        \"endpoint\": \"https://leader.example.com/\",
        \"role\": \"Leader\",
        \"collector_hpke_config\": {
            \"id\": 1,
            \"kem_id\": \"X25519HkdfSha256\",
            \"kdf_id\": \"HkdfSha256\",
            \"aead_id\": \"Aes128Gcm\",
            \"public_key\": \"Q6WsU8wTEYLGaSUZ0M64osfG67AfwZBxWvXp3lxIfxQ\"
        },
        \"verify_key_init\": \"$VERIFY_KEY_INIT\",
        \"report_expiry_age\": null,
        \"tolerable_clock_skew\": 600,
        \"aggregator_auth_tokens\": [{
            \"type\": \"Bearer\",
            \"token\": \"$AGGREGATOR_AUTH_TOKEN\"
        }],
        \"collector_auth_tokens\": []
    }"
```

Aggregator replicas will not become aware of the new aggregator until they are
restarted, since their aggregator cache does not refresh.

Other helpful methods are as follows:
- `GET /taskprov/peer_aggregators`: list configured peer aggregators
- `DELETE /taskprov/peer_aggregators`: delete a peer aggregator. Requires a JSON
  request body containing the endpoint and role of the aggregator. Note that if
  you need to modify an existing peer aggregator, you will need to delete it and
  recreate it with the desired parameters**.

Note that the aggregator API will not report sensitive values.

** To be fixed in [#1685](https://github.com/divviup/janus/issues/1685).

### Global HPKE Keys

Taskprov requires that at least one active global HPKE key is configured.

See [CONFIGURING_GLOBAL_HPKE_KEYS](CONFIGURING_GLOBAL_HPKE_KEYS.md) for how this
is configured.