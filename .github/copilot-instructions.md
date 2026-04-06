# Project Guidelines

## Code Style

- Use TypeScript and React functional components.
- Keep components small and add `"use client"` only when hooks, effects, browser APIs, or client-only Mantine features are required.
- Follow the existing ESLint and formatting style in the repo; do not reformat unrelated code.

## Architecture

- This is a Next.js 16 App Router frontend packaged with Tauri 2. Keep browser code in `src/app` and Rust entrypoints in `src-tauri`.
- Keep `src/app/layout.tsx` as a server component. Preserve `suppressHydrationWarning` on `<html>` and Mantine's `ColorSchemeScript` in `<head>` when working on root layout or theme setup.
- Keep Mantine provider and theme setup centralized in `src/app/providers.tsx` rather than duplicating it in pages.
- The app is statically exported for Tauri (`output: "export"`), so avoid changes that depend on SSR or a Node server at runtime.

## Build and Test

- Use `pnpm dev`, `pnpm build`, `pnpm lint`, and `pnpm tauri` for local verification.
- If a change touches UI startup or app shell behavior, verify both the Next.js build and the Tauri path that consumes the static output.

## Conventions

- Prefer Mantine v9 components and keep the UI desktop-friendly, intentional, and minimal.
- Keep user-facing copy specific to the DPI-blocking/security domain; avoid placeholder text in shipped screens.
- Watch for hydration mismatches before changing root layout, color scheme behavior, or theme initialization.
