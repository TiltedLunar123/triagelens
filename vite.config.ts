/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'node',
    // Netlify treats every file under netlify/functions as a function to
    // deploy, and a name with a dot in it is rejected outright, so the tests
    // for those handlers live one directory up.
    include: ['src/**/*.test.ts', 'netlify/tests/*.test.mjs'],
  },
})
