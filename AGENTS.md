# Deploying the edge gateway

Use this file when asked to install or update the gateway on a customer host. Complete the deployment and verify data delivery when the required access and inputs are available. A request to edit this repository alone does not request a customer deployment.

Read README.md for the license, writer token, billing, and writer setup. Keep public documentation in plain English. Do not add architectural diagrams or arrow navigation.

## Required inputs

Use values supplied by the operator or already configured on the target host:

- Target host and SSH access, with permission to use Docker and sudo.
- Release commit: the full 40-character commit from a successful public release.
- Host LAN IPv4 address, gateway DNS name, and writer hosts allowed to connect.
- Gateway Setup Wizard export for a new installation: the prefilled `config.yaml` (port `2948`, `bindings: []`, and the `vmagent` principal with its `tokenSha256`), the one-time `license.json`, and the writer bearer token that starts with `ci_ingest_`. Download each file when shown.
- Stream definitions: the sensor or machine each stream targets and its PromQL series selector, built from exact label matchers, for example `vm_motor_temp_celsius{site="north",asset="comp_a",sensor="de_bearing"}`. Each stream uses one gateway sensor slot. Do not invent binding IDs or stream keys.
- Actual writer labels, units and scale for any stream that needs a local static binding instead of the cloud descriptor.
- A TLS certificate for the gateway DNS name, its private key, and the CA certificate trusted by the writers, when the wizard's `TLS (Recommended)` mode is used. Get these from the site's certificate issuer.
- Access to configure the writer's token, CA trust, and remote-write endpoint.
- An active Gateway add-on with enough gateway sensor slots for vibration streams.

Check existing files and deployment records first. Ask only for missing inputs. Do not create a new paid plan, rotate credentials, or replace an existing gateway identity merely to complete an installation.

## Host checks

Run deployment commands on the target host. Use Bash with `set -euo pipefail` and `umask 077`. Do not enable shell tracing. Never print licenses, stream keys, writer tokens, private keys, or proxy credentials. Store these outside the repository.

The published image and binary currently support Linux amd64. Check `uname -m` reports `x86_64` and Docker is running. Confirm the host clock is synchronized, disk space covers the configured buffer (10 GiB by default) plus image storage, and the ingest host in the license is reachable on TCP 443. UDP 443 is optional. Preserve any configured proxy and certificate trust.

Check whether `edgegateway` already exists with `docker container inspect edgegateway`. If it exists, follow the update section. Do not overwrite its configuration or enrollment files as a fresh install.

## Download and verify a release

Set `RELEASE_SHA` to the supplied release commit. Run these commands in one Bash session. Keep `IMAGE_ID` for startup.

```bash
set -euo pipefail
umask 077
: "${RELEASE_SHA:?Set the full release commit first}"
[[ "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]]
DEPLOY_DIR=$(mktemp -d)
cd "$DEPLOY_DIR"
RELEASE_URL="https://github.com/1a11/clearintervals-edge/releases/download/build-$RELEASE_SHA"
for file in edgegateway-image.tar.gz SHA256SUMS image-digest.txt; do
  curl --fail --location --retry 3 "$RELEASE_URL/$file" -o "$file"
done
# Require both records before checking; do not accept a missing image checksum.
awk '$2 == "edgegateway-image.tar.gz" || $2 == "image-digest.txt"' SHA256SUMS > deploy-checksums
[[ $(wc -l < deploy-checksums) -eq 2 ]]
sha256sum --check deploy-checksums
gunzip -c edgegateway-image.tar.gz | docker load
IMAGE="ghcr.io/1a11/clearintervals-edge:sha-$RELEASE_SHA"
IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE")
[[ $(docker run --rm --network none "$IMAGE_ID" -version) == "$RELEASE_SHA" ]]
```

These downloads need no GitHub or registry login. Use the release archive if registry access is unavailable. Do not mix files from different releases. Checksums detect damaged downloads; they are not an independent publisher signature. Where site policy requires signature verification, follow the Cosign command in README.md for the exact digest in `image-digest.txt`. Stop on a verification failure.

## Prepare a new installation

Use these host paths:

| Host path | Container path | Contents |
| --- | --- | --- |
| `/srv/edgegateway/config` | `/etc/edgegateway` | Prefilled configuration, read only |
| `/srv/edgegateway/tls` | `/etc/ssl/certs/own` | Gateway certificate and key for `TLS (Recommended)`, read only |
| `/srv/edgegateway/state` | `/var/lib/edgegateway` | Gateway identity and queued data, writable |
| `/srv/edgegateway/state/enrollment/license.json` | `/var/lib/edgegateway/enrollment/license.json` | Downloaded one-time enrollment license |

Create the directories:

```bash
sudo install -d -o 65532 -g 65532 -m 0700 \
  /srv/edgegateway/config /srv/edgegateway/tls /srv/edgegateway/state /srv/edgegateway/state/enrollment
``` Copy the downloaded license unchanged to the path above with `sudo install -o 65532 -g 65532 -m 0600 "$LICENSE_FILE" /srv/edgegateway/state/enrollment/license.json`. Set `LICENSE_FILE` to its actual local path first. Do this only for a new installation. The gateway removes the file after enrollment; do not restore it on each restart.

For `TLS (Recommended)`, install the gateway certificate and key as `tls.crt` and `tls.key` in `/srv/edgegateway/tls`. The container mounts that directory at `/etc/ssl/certs/own`, which is where the prefilled `config.yaml` looks. Set ownership to 65532:65532 and mode 0600 so the container can read them. When the site stores TLS material elsewhere, edit the two paths in `config.yaml` and mount that directory instead. Do not use self-signed or placeholder certificates without configuring the writers to trust the issuer.

Copy the prefilled `config.yaml` from the wizard to `/srv/edgegateway/config/config.yaml` with ownership 65532:65532 and mode 0600. It already sets:

- `stateDir: /var/lib/edgegateway` and `deploymentLicensePath: /var/lib/edgegateway/enrollment/license.json`.
- `modules.remoteWrite.enabled: true` with `listen: 0.0.0.0:2948` for `TLS (Recommended)`, or `127.0.0.1:2948` for `Loopback HTTP`.
- The `vmagent` principal with the one-time bearer token's SHA-256 digest in `tokenSha256`.
- `bindings: []`, which the gateway fills from cloud stream descriptors after enrollment.

Keep `statusListen: 127.0.0.1:9081` private. The prefilled file already names the certificate and key paths for `TLS (Recommended)`; edit them only when the site stores TLS material elsewhere.

Add a local principal only when a writer other than `vmagent` must send. Generate a random token locally, keep the original in that writer's protected credential file, and put only its SHA-256 hex digest in `tokenSha256`. Reuse an existing valid token on repeat deployments. Do not invent a token for `vmagent`; the wizard's token is the one the writer already holds.

Leave `bindings: []` unless the site needs a local override. The gateway fetches the streams you define in the wizard or on the gateway overview page. A static binding, when needed, uses the issued `id`, `sourceId` and `streamKey`, the `kind`, and for `series` the exact label selector and a nonzero scale; for `captures`, omit selector and scale.

For captures, enable `modules.captures` with its own TLS listener on port 8430 and its own writer principals. Publish that port only when captures are used. Do not leave remote write enabled if it is unused.

Validate before opening a port:

```bash
docker run --rm --network none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -v /srv/edgegateway/config:/etc/edgegateway:ro \
  "$IMAGE_ID" -check
```

A successful `-check` validates configuration fields. Startup also checks the installed TLS files and writable state. Fix errors before continuing.

## Start the gateway

For remote write, set `LAN_IP` to the supplied LAN address, then run:

```bash
: "${LAN_IP:?Set the host LAN IPv4 address first}"
docker run -d --name edgegateway --restart unless-stopped \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --memory=512m --cpus=1 \
  --log-opt max-size=10m --log-opt max-file=3 \
  -v /srv/edgegateway/config:/etc/edgegateway:ro \
  -v /srv/edgegateway/state:/var/lib/edgegateway \
  -v /srv/edgegateway/tls:/etc/ssl/certs/own:ro \
  -p "$LAN_IP:2948:2948" \
  "$IMAGE_ID"
```

The `/srv/edgegateway/tls` mount is needed only with `TLS (Recommended)`; omit it and the port mapping in `Loopback HTTP` mode, where a writer in the same network namespace uses `http://127.0.0.1:2948/api/v1/write`. For captures, add `-p "$LAN_IP:8430:8430"`. Remove the 2948 mapping for a captures-only deployment. Restrict published ports to the agreed writer hosts using the site's Docker-aware firewall policy. Do not publish port 9081 or open inbound Internet access.

Configure each writer to use the endpoint from the wizard, `https://GATEWAY_DNS_NAME:2948/api/v1/write`, its one-time bearer token, and the CA certificate for the gateway's certificate. Replace `GATEWAY_DNS_NAME` with the supplied name. Preserve existing remote-write destinations. Reload the writer using its supported configuration check and reload procedure. Do not disable TLS verification.

## Verify deployment

1. Run `docker inspect --format '{{.State.Status}} {{.RestartCount}}' edgegateway`. It must stay running without repeated restarts.
2. Check `docker logs --since 5m edgegateway`. Look for `gateway_ready` and `uplink_connected`; a new enrollment also emits `credential_activated`. After the first stream is added, `descriptors_synced` confirms the cloud descriptor set arrived. Investigate retry and rejection events.
3. Check the private health endpoint from the container's network namespace. The image has no shell or curl. Use host tools:

   ```bash
   CONTAINER_PID=$(docker inspect --format '{{.State.Pid}}' edgegateway)
   sudo nsenter -t "$CONTAINER_PID" -n -- curl --noproxy '*' --fail --silent --show-error http://127.0.0.1:9081/healthz
   ```

4. Confirm the gateway's recent heartbeat in the app. Step 3 of the wizard reports `Reporting`. Add or confirm a stream in Step 4, or from the gateway overview page, using an exact PromQL selector. While the first descriptor sync is pending, remote write answers `503` with `Retry-After: 15`, so the writer retries and keeps the batch in its WAL. Then send a real sample from an authorized writer and confirm it appears at the intended sensor or machine. A 200 health response alone does not prove cloud delivery.
5. Allow up to five minutes for initial connection and data checks. If cloud or app access is unavailable, state which checks remain unverified. Do not report full deployment success.

Record the target host, release SHA, image ID, enabled ports, configuration path, and verification results. Include no credentials.

## Updates and rollback

Download and validate the new release before stopping the old container. Record the old image ID and exact launch options. Keep a protected copy of the existing config and TLS files. Preserve the state directory in place; never run two gateways against it or copy it to another live host.

If the requested image ID and configuration are already running and healthy, verify delivery and finish without restarting.

For an update, stop the existing container with `docker stop --time 60 edgegateway`, rename it to an unused rollback name, and start the new image with the same mounts, LAN addresses, ports, and resource limits. Apply the startup and verification steps above. Do not overwrite the license or remove the state directory.

If verification fails, stop and remove only the new container, restore the previous config if it changed, rename the saved container to `edgegateway`, and start it. Verify delivery again. Rollback keeps the current persistent state; never restore an old state snapshot over queued data or a renewed identity. If the release documents an incompatible state change, resolve the migration and rollback plan before stopping the old gateway.

Do not delete the saved container or old image until the new deployment has passed verification. Never use `docker system prune`, delete the state directory, revoke a gateway, or issue replacement credentials as routine cleanup.
