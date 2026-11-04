# testd site

The product site lives under `sites/`; the documentation Markdown lives under `docs/` at the repository root. Both are built and served as one tree from the repository root. The product page is at `/`, and the VitePress docs are at `/docs/`.

## Develop

The dev server runs in a container; no local install is needed to run it.

```sh
./sites/bin/site.sh dev  # product at http://127.0.0.1:5173/, docs at /docs/
# or
bun run dev
```

`site.sh` runs the official Bun image (`oven/bun:1.4.4`) with the site sources mounted, installs dependencies into the `testd-site-node-modules` volume, and runs the stock `vitepress dev` and `vite` CLI entrypoints with Bun. It prefers `podman`, falls back to `docker`, and can be pinned with `TESTD_SITE_RUNTIME`. The product server is the public origin and proxies `/docs/` to VitePress on loopback.

`--host <address>` (or `TESTD_SITE_HOST`) moves the published port off loopback; `--host 0.0.0.0` serves the network. `--port <port>` overrides the published port for `dev` or `preview`; `TESTD_SITE_PORT` and `TESTD_SITE_PREVIEW_PORT` set the defaults. `TESTD_DOCS_PORT` moves the internal docs port, and `TESTD_SITE_IMAGE` or `TESTD_SITE_VOLUME` overrides the image or dependency volume. `./sites/bin/site.sh clean` removes the volumes and `dist/`.

## Build

```sh
bun install
bun run build
bun run preview  # serves the built tree at http://localhost:4173/
bun run check
bun run check:links
```

`bun run build` writes the product site to `dist/` first, then the docs to `dist/docs/`. Deploy `dist/` as one static tree. `bun run preview -- --host 0.0.0.0` exposes the built tree on every interface.

The same work runs in the container, so a host without Bun can still build and check:

```sh
./sites/bin/site.sh build    # writes dist/, owned by the calling user
./sites/bin/site.sh preview  # serves the built tree
./sites/bin/site.sh check
./sites/bin/site.sh links    # checks links in the built tree
./sites/bin/site.sh shell
```

`site.sh build` exports the tree out of its build volume, so `dist/` belongs to the host user. `preview` and `links` read that exported tree.

## Publish

Production is a Cloudflare Pages project built from this repository by Git integration. Every push to `master` publishes; other branches get a preview URL. The dashboard settings:

| Setting | Value |
|---|---|
| Production branch | `master` |
| Build command | `bun install --frozen-lockfile && bun run build` |
| Build output directory | `dist` |
| Root directory | `/` (default) |

The Pages build image includes Bun (1.4.4, the same version as the container image); set `BUN_VERSION` only to pin another one. Vite copies `sites/product/public/_headers` and `_redirects` into `dist/`, and Pages applies both. `testd.dev` is the project's custom domain, so the tree carries no `CNAME` file.

Workers static assets would serve the same tree and also honour `_headers` and `_redirects`, but they need a `wrangler.jsonc`, a deploy command, and a Worker name that matches the project. Choose Workers when the site needs code at the edge; until then Pages keeps the configuration in the dashboard and the repository free of deploy files.

CI builds and link-checks `dist/` on every run and does not deploy it; publication belongs to the Pages Git integration alone.

## Layout

- `assets/`: canonical brand and social images
- `sites/product/`: product landing page, styles, deploy files, and its Vite config
- `docs/`: documentation Markdown
- `sites/docs/`: VitePress configuration and theme; reads the pages from `docs/` and serves `assets/brand/` as its public directory
- `sites/bin/site.sh`: entry point; picks the runtime and runs one action in a container
- `sites/bin/entrypoint.sh`: installs dependencies in the container, then runs the action
- `sites/bin/dev-servers.sh`: runs stock `vitepress dev` and `vite` inside the container
- `src-tauri/icons/`: generated bundle and tray icons
- `scripts/build-icons.py`: regenerates `src-tauri/icons/` from `assets/brand/`
- `scripts/check-links.ts`: link checker for the built tree
- `dist/`: combined build output, served at the origin root

## Brand assets

`assets/brand/testd-slim.svg` is the slim brand icon used across the sites; `testd-mark.svg` is its bare `t.` glyph. The product site imports the brand files through Vite, and the docs serve `assets/brand/` as their public directory, using `testd-slim.svg` for both the header logo and the favicon.

`assets/brand/testd-app.png` is the 1024px fat app icon, and `testd-tray-mask.png` and `testd-tray-plate-mask.png` are the alpha masks for the tray variants. `scripts/build-icons.py` regenerates `src-tauri/icons/` from those sources; the generated files stay in the directory Tauri expects. `assets/social/og.png` is the social card, emitted at `/og.png` by the product Vite config.

The palette follows the Lapilli studio sheet: basalt `#141414`, paper `#F2EEE4`, lapilli `#E4542B`, ash `#8C8A83`. The footer uses the Direction 01 shard wordmark: the reversed file on the dark ground and the standard file on the light 404 page. Fonts are self-hosted through Fontsource: Archivo for text and JetBrains Mono for code.
