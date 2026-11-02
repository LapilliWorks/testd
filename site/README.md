# testd site

The product site is a small Vite app. The documentation is VitePress. Both are managed by the Bun workspace at the repository root.

## Develop

```sh
bun install
bun run dev       # product site at http://localhost:5173
bun run dev:docs  # docs at http://localhost:5174/docs/
```

## Build

```sh
bun run build
bun run check
bun run check:links
```

`bun run build` builds the product site into `site/dist/`, then the docs into `site/dist/docs/`. Deploy `site/dist/` as one static tree.

## Layout

- `site/index.html`, `site/src/`: product landing page and its styles
- `docs/`: VitePress source, configuration, and theme
- `site/public/`: static files served at the root, including `install.sh` and the OG image
- `docs/public/`: static files served under `/docs/`

## Brand assets

`site/src/assets/testd-icon.svg` and `testd-mark.svg` are geometric redrawings of the repository's `app-icon.png`. The mark is the `t.` glyph; the icon adds the square frame. The site header and footer use the full icon. `favicon.svg` is the small-size mark with a paper tile.

The palette follows the Lapilli studio sheet: basalt `#141414`, paper `#F2EEE4`, lapilli `#E4542B`, ash `#8C8A83`. Fonts are self-hosted through Fontsource: Archivo for text and JetBrains Mono for code.
