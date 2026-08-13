import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'

// ESLint flat config.
//
// CSP posture (inviolate): styling ships as Tailwind's static compiled CSS so
// `style-src 'self'` holds with no 'unsafe-inline'. Two guardrails enforce that
// at lint time:
//   1. react/forbid-dom-props bans inline `style={{}}` — no style attributes
//      reach the DOM.
//   2. DO NOT introduce CSS-in-JS (styled-components, emotion, stitches, etc.).
//      Those inject runtime <style> tags / inline style attributes that would
//      force a `style-src 'unsafe-inline'` downgrade. All styling = Tailwind
//      utilities + the base stylesheet. (No lint rule can catch an arbitrary
//      new dependency, so this is a hard project convention — reviewers enforce.)
export default tseslint.config(
  { ignores: ['dist'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      ...tseslint.configs.recommended,
      react.configs.flat.recommended,
      react.configs.flat['jsx-runtime'],
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    settings: {
      react: { version: 'detect' },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
      // Ban inline styles — load-bearing for `style-src 'self'`.
      'react/forbid-dom-props': ['error', { forbid: ['style'] }],
    },
  },
)
