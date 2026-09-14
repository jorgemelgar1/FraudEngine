import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
var host = process.env.TAURI_DEV_HOST;
export default defineConfig({
    plugins: [react()],
    clearScreen: false,
    // The pattern dictionary is shared with the web app and lives at the repo
    // root, outside this Vite root. The alias must match the `paths` entry in
    // tsconfig.json: tsc resolves types through one and Vite resolves the
    // bundle through the other, so a change to either alone type-checks fine
    // and fails at build.
    resolve: {
        alias: {
            '@shared': fileURLToPath(new URL('../shared', import.meta.url)),
        },
    },
    server: {
        // Vite refuses to serve files outside its root in dev unless told.
        fs: { allow: ['..'] },
        port: 1420,
        strictPort: true,
        host: host || false,
        hmr: host ? { protocol: 'ws', host: host, port: 1421 } : undefined,
    },
});
