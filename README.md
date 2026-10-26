# Clear Intervals edge gateway

The gateway runs on your network. It receives machine data and sends it to Clear Intervals. It stores data on disk during a connection outage.

## Before you start

- Linux with Docker (or any OCI runtime), or Go 1.27.3 to build from source.
- Outbound UDP 443 and/or TCP 443 to your region's ingest host, directly or through an HTTP proxy. Proxies that
  inspect TLS must exempt the ingest host.
- NTP on the host. Captures are refused if the clock is more than 30 s off.
- An enrollment licence for this gateway, downloaded from the product, and a stream key for each sensor you bind.

## Get your license and stream key

An organization admin sets these up in the Clear Intervals app. The app uses the spelling **licence** on its buttons.

### License: connects one gateway to your account

The license is a JSON file that lets this gateway register with Clear Intervals. It contains a one-time enrollment token and the connection details. Use it before the expiry time shown in the app. After registration, the gateway renews its own certificate.

In the app, open **Gateways → New gateway**, enter its name and sites, then select **Create and get licence**. In **Save the licence**, select **Download**. The file is named `gateway-<id>.licence.json`.

Copy that file to the gateway host. In the Docker setup below, rename it to `license.json` and put it at `/srv/edgegateway/state/enrollment/license.json`. Docker makes it available inside the container at `/var/lib/edgegateway/enrollment/license.json`, the path in `deploymentLicensePath`. Keep the JSON file unchanged. The gateway deletes it after successful registration.

If you lose the file or it expires before use, open the gateway’s **Credentials** panel and select **Download licence** to issue a new one. For an already enrolled gateway, the action is **Replace…**; read the confirmation before replacing its credentials.

### Stream key: allows data into one configured stream

A stream connects a channel on your gateway to a sensor or machine in Clear Intervals. Its stream key is the secret that authorizes data for that stream. Each stream has its own key.

Open **Gateways → your gateway → Add stream**. Choose **Vibration captures** or **Context readings**, select the sensor or machine, complete the stream settings, and select **Add stream**. In **Save the stream key**, select **Download**. The file is named `stream-<id>.key.json`.

Open that file and copy its `streamKey` value into the matching `bindings` entry’s `streamKey` field in `/srv/edgegateway/config/config.yaml`. Copy the value itself, without the surrounding JSON. The stream key is separate from the writer token you create in step 2 below: that token lets Prometheus or vmagent write to your local gateway.

Save the downloaded file safely; the key is shown only when it is created. If it is lost, open **Credentials → the stream → New key…**, then update the gateway configuration with the replacement.

### Billing

Edge gateways require the **Gateway add-on** on your organization’s plan. It is priced per gateway sensor. Vibration capture streams use the gateway sensor allowance; context readings, such as speed or temperature, do not use a sensor slot.

The **Gateways** page shows how many gateway sensors are in use and your plan’s limit. Ask your Clear Intervals account manager to enable the add-on, increase the allowance, or confirm your price and billing terms. The downloaded license is an enrollment credential; your commercial allowance is managed through the plan.

## Get started

These steps use Docker and the remote-write module. Paths on the host are examples.

Download `edgegateway-image.tar.gz` and `SHA256SUMS` from the [latest release](https://github.com/1a11/clearintervals-edge/releases/latest). Downloads are public and need no GitHub account. Check and load the image:

```sh
sha256sum --ignore-missing -c SHA256SUMS
gunzip -c edgegateway-image.tar.gz | docker load
```

Use the image name printed by `docker load` as `IMAGE` below. Each release uses a tag tied to its source commit:

```sh
IMAGE=ghcr.io/1a11/clearintervals-edge:sha-<commit from the release>
```

**1. Prepare the host directories.** The image runs as UID/GID 65532 with no shell.

```sh
sudo mkdir -p /srv/edgegateway/config /srv/edgegateway/state/enrollment
sudo cp gateway-REPLACE_WITH_ID.licence.json /srv/edgegateway/state/enrollment/license.json
sudo chown -R 65532:65532 /srv/edgegateway/state
sudo chmod 700 /srv/edgegateway/state && sudo chmod 600 /srv/edgegateway/state/enrollment/license.json
```

Replace `gateway-REPLACE_WITH_ID.licence.json` with the filename downloaded from the app. The licence is deleted automatically once enrollment completes, which is why it lives in the writable state volume.

**2. Create a writer credential.** Each writer gets its own token. The gateway stores only the token's SHA-256.

```sh
TOKEN=$(openssl rand -base64 48)
printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1   # goes into tokenSha256
```

Keep `$TOKEN` in the writer's secret store, not in the gateway configuration.

**3. Write the configuration.** Start from [`config.example.yaml`](config.example.yaml) and save it as
`/srv/edgegateway/config/config.yaml`. A non-loopback listener requires a TLS certificate and key, which go in
the same directory.

```yaml
stateDir: /var/lib/edgegateway
deploymentLicensePath: /var/lib/edgegateway/enrollment/license.json
modules:
  remoteWrite:
    enabled: true
    listen: 0.0.0.0:8429
    certificate: /etc/edgegateway/lan-server.pem
    key: /etc/edgegateway/lan-server.key
    principals:
      - id: vmagent
        tokenSha256: <output of step 2>
bindings:
  - id: <binding version from the product>
    streamKey: <streamKey value from stream-ID.key.json>
    sourceId: <canonical source ID from the product>
    kind: series
    selector:
      __name__: machine_speed_rpm
      machine: pump-1
    scale: 1
    principals: [vmagent]
```

**4. Check it.** `-check` validates the file without opening ports or contacting the cloud.

```sh
docker run --rm -v /srv/edgegateway/config:/etc/edgegateway:ro \
  "$IMAGE" -check
```

A problem is reported with the field it concerns:

```json
{"level":"ERROR","event":"configuration_invalid","field":"bindings[0].streamKey","problem":"must be the 40-100 character stream key copied from the product"}
```

**5. Run it.**

```sh
docker run -d --name edgegateway --restart unless-stopped \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --memory=512m --cpus=1 \
  -v /srv/edgegateway/config:/etc/edgegateway:ro \
  -v /srv/edgegateway/state:/var/lib/edgegateway \
  -p 10.0.0.5:8429:8429 \
  "$IMAGE"
```

Replace `10.0.0.5` with the server’s LAN address. Allow connections only from your writers. Use the image from the release you downloaded.

**6. Point a writer at it.** For Prometheus:

```yaml
remote_write:
  - url: https://edgegateway.lan:8429/api/v1/write
    authorization:
      credentials_file: /etc/prometheus/edgegateway.token
    tls_config:
      ca_file: /etc/prometheus/edgegateway-ca.pem
    queue_config:
      max_samples_per_send: 1000
```

For vmagent, add `-remoteWrite.url=https://edgegateway.lan:8429/api/v1/write`, `-remoteWrite.bearerToken=...`
and `-remoteWrite.tlsCAFile=...`. Your existing remote-write targets stay as they are.

**7. Watch the logs.** `docker logs -f edgegateway` should show `identity_loaded`, `listener_started`,
`gateway_ready`, then `credential_activated` and `uplink_connected` once enrollment succeeds.

## Check the connection

Run `docker logs -f edgegateway`. After enrollment, look for `credential_activated` and `uplink_connected`. Keep the state directory: it holds this gateway’s identity and queued data. Do not share it with another gateway.

If startup fails:

- `configuration_invalid`: fix the named field and run `-check` again.
- `permission_denied`: make sure UID 65532 can write to the state directory.
- `identity_invalid`: check the enrollment licence and the host clock.
- `connect_timeout`: allow outbound TCP 443 or set `uplink.proxy` in the configuration.
- `quic_unavailable`: UDP is blocked. The gateway will use TCP.
- Writer receives `401` or `403`: check the token and the binding’s `principals` list.

## Build from source

Install the Go version listed in `go.mod`, then run:

```sh
make verify build
bin/edgegateway -version
```

The release workflow also checks generated protocol files, runs fuzz tests, scans dependencies and the container, and signs the image. Each successful release includes the Linux amd64 binary, a Docker image archive, checksums, the image digest, and scan and signature records. Releases are tied to a source commit; updates are installed manually.

To verify a registry image with Cosign:

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/1a11/clearintervals-edge/.github/workflows/release.yaml@refs/heads/main \
  ghcr.io/1a11/clearintervals-edge@sha256:<digest from image-digest.txt>
```

For security reports, see [SECURITY.md](SECURITY.md).
