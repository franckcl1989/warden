import js from '@eslint/js';
import skipFormatting from '@vue/eslint-config-prettier/skip-formatting';
import { withVueTs, vueTsConfigs } from '@vue/eslint-config-typescript';
import pluginVue from 'eslint-plugin-vue';
import globals from 'globals';

export default withVueTs(
  {
    ignores: [
      'dist/',
      'coverage/',
      'node_modules/',
      'playwright-report/',
      'test-results/',
      'src/api/generated/',
    ],
  },
  js.configs.recommended,
  ...pluginVue.configs['flat/recommended'],
  vueTsConfigs.recommended,
  {
    files: ['**/*.{ts,mts,cts,vue}'],
    languageOptions: {
      globals: {
        ...globals.browser,
      },
    },
  },
  {
    files: ['vite.config.ts', 'playwright.config.ts', 'scripts/**/*.mjs', 'e2e/**/*.ts'],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
  },
  skipFormatting,
);
