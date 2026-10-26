# Deploying the edge gateway

Use this file when asked to install or update the gateway on a customer host. Complete the deployment and verify data delivery when the required access and inputs are available. A request to edit this repository alone does not request a customer deployment.

Read README.md for the license, stream key, billing, and writer setup. Keep public documentation in plain English. Do not add architectural diagrams or arrow navigation.

## Required inputs

Use values supplied by the operator or already configured on the target host:

- Target host and SSH access, with permission to use Docker and sudo.
- Release commit: the full 40-character commit from a successful public release.
- Host LAN IPv4 address, gateway DNS name, and writer hosts allowed to connect.
- Enrollment license for a new installation. Obtain it in the app under Gateways, New gateway, Create and get licence. Download the file when shown.
- Stream credentials and binding settings for each source. In the app, open the gateway and select Add stream. Save the stream key file when shown. Use the issued binding ID, canonical source ID, and stream key. Do not invent IDs or use a sensor name in place of an ID.
- Actual writer labels for series selectors, units and scale, and which writers may use each binding.
- A TLS certificate for the gateway DNS name, its private key, and the CA certificate trusted by the writers. Get these from the site's certificate issuer.
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
| `/srv/edgegateway/config` | `/etc/edgegateway` | Configuration and LAN TLS files, read only |
| `/srv/edgegateway/state` | `/var/lib/edgegateway` | Gateway identity and queued data, writable |
| `/srv/edgegateway/state/enrollment/license.json` | `/var/lib/edgegateway/enrollment/license.json` | Downloaded enrollment license |

Create the directories:

```bash
sudo install -d -o 65532 -g 65532 -m 0700 \
  /srv/edgegateway/config /srv/edgegateway/state /srv/edgegateway/state/enrollment
``` Copy the downloaded license unchanged to the path above with `sudo install -o 65532 -g 65532 -m 0600 "$LICENSE_FILE" /srv/edgegateway/state/enrollment/license.json`. Set `LICENSE_FILE` to its actual local path first. Do this only for a new installation. The gateway removes the file after enrollment; do not restore it on each restart.

Install the TLS certificate and key as `lan-server.pem` and `lan-server.key` in the config directory. Set ownership to 65532:65532 and mode 0600 so the container can read them. Do not use self-signed or placeholder certificates without configuring the writers to trust the issuer.

Create `/srv/edgegateway/config/config.yaml` using config.example.yaml and the README example. Set ownership to 65532:65532 and mode 0600. Set:

- `stateDir: /var/lib/edgegateway`.
- `deploymentLicensePath: /var/lib/edgegateway/enrollment/license.json`.
- `statusListen: 127.0.0.1:9081`; keep status private.
- `modules.remoteWrite.enabled: true` and `listen: 0.0.0.0:8429` when using remote write.
- The certificate and key paths under `/etc/edgegateway`.
- One principal per writer. Generate a random token locally, save the original in that writer's protected credential file, and put only its SHA-256 hex digest in `tokenSha256`. Reuse an existing valid token on repeat deployments.
- Each binding's issued `id`, `sourceId`, `streamKey`, `kind`, and allowed principal IDs. For `series`, use the real label selector and a nonzero scale. For `captures`, omit selector and scale.

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
  -p "$LAN_IP:8429:8429" \
  "$IMAGE_ID"
```

For captures, add `-p "$LAN_IP:8430:8430"`. Remove the 8429 mapping for a captures-only deployment. Restrict published ports to the agreed writer hosts using the site's Docker-aware firewall policy. Do not publish port 9081 or open inbound Internet access.

Configure each writer to use `https://GATEWAY_DNS_NAME:8429/api/v1/write`, its original token, and the CA certificate for the gateway's LAN certificate. Replace `GATEWAY_DNS_NAME` with the supplied name. Preserve existing remote-write destinations. Reload the writer using its supported configuration check and reload procedure. Do not disable TLS verification.

## Verify deployment

1. Run `docker inspect --format '{{.State.Status}} {{.RestartCount}}' edgegateway`. It must stay running without repeated restarts.
2. Check `docker logs --since 5m edgegateway`. Look for `gateway_ready` and `uplink_connected`; a new enrollment also emits `credential_activated`. Investigate retry and rejection events.
3. Check the private health endpoint from the container's network namespace. The image has no shell or curl. Use host tools:

   ```bash
   CONTAINER_PID=$(docker inspect --format '{{.State.Pid}}' edgegateway)
   sudo nsenter -t "$CONTAINER_PID" -n -- curl --noproxy '*' --fail --silent --show-error http://127.0.0.1:9081/healthz
   ```

4. Confirm the gateway's recent heartbeat in the app. Send a real sample from an authorized writer and confirm it appears at the intended sensor or machine. A 200 health response alone does not prove cloud delivery.
5. Allow up to five minutes for initial connection and data checks. If cloud or app access is unavailable, state which checks remain unverified. Do not report full deployment success.

Record the target host, release SHA, image ID, enabled ports, configuration path, and verification results. Include no credentials.

## Updates and rollback

Download and validate the new release before stopping the old container. Record the old image ID and exact launch options. Keep a protected copy of the existing config and TLS files. Preserve the state directory in place; never run two gateways against it or copy it to another live host.

If the requested image ID and configuration are already running and healthy, verify delivery and finish without restarting.

For an update, stop the existing container with `docker stop --time 60 edgegateway`, rename it to an unused rollback name, and start the new image with the same mounts, LAN addresses, ports, and resource limits. Apply the startup and verification steps above. Do not overwrite the license or remove the state directory.

If verification fails, stop and remove only the new container, restore the previous config if it changed, rename the saved container to `edgegateway`, and start it. Verify delivery again. Rollback keeps the current persistent state; never restore an old state snapshot over queued data or a renewed identity. If the release documents an incompatible state change, resolve the migration and rollback plan before stopping the old gateway.

Do not delete the saved container or old image until the new deployment has passed verification. Never use `docker system prune`, delete the state directory, revoke a gateway, or issue replacement credentials as routine cleanup.
