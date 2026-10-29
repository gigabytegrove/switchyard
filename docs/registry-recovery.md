# Registry-independent Switchyard deployment

A Docker Hub failure such as `failed to fetch anonymous token` followed by `connection reset by peer` is a registry-network problem during an image pull; it does not indicate bad Switchyard credentials.

## Raw Compose platforms

Use [`../compose.yaml`](../compose.yaml). It references the prebuilt application image `ghcr.io/gigabytegrove/switchyard:0.5.0-dev.1` and the digest-pinned `ghcr.io/quenchworks/images/guacd` image. It contains no `build:`, external secrets, or `.env` fields. Container settings are configured via the web wizard and persisted under `/data`.

Before deploying, verify your Docker daemon can reach GHCR:

```sh
docker manifest inspect ghcr.io/quenchworks/images/guacd@sha256:caf62c36625a2ffb3adfc2bcc51572ab4e7f5e805ae3b55f3800812eeaf3c411 >/dev/null
docker manifest inspect ghcr.io/gigabytegrove/switchyard:0.5.0-dev.1 >/dev/null
```

If either request fails, do not assume the image exists or is public. Investigate the registry response and network path. The application image must be published by the passing GitHub Actions build and available anonymously; a newly published GHCR package may require an owner to change its visibility to public in GitHub Packages.

Use `docker compose up -d --no-build --wait` after successful pulls. Do **not** use `docker compose down -v` as it removes persistent settings.

## Build dependencies

Only GitHub's release builder needs Docker Hub to fetch the Node base image. Raw Compose deployment does not build locally. Do not replace the Guacamole image with a modified protocol service without running RDP and VNC acceptance tests.

## Security

The `guacd` service is **not authenticated** by itself. Never publish its port 4822. Restrict the Switchyard app port 9791 to trusted LAN clients, or access it only through an HTTPS reverse proxy with the configured MFA policy. A Docker named volume persists across container recreation with the same Compose project identity. A new project name may create a different named volume and an apparently fresh installation.

The pinned Guacamole daemon rebuild is third-party software. Publisher provenance: https://quench-works.com/images/guacd/ . The upstream official Apache image is `guacamole/guacd:1.6.0` on Docker Hub.
