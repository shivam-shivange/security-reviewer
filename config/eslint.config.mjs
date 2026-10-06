// Predefined ESLint flat config for the general-bug tier (JS, JSX, TS, TSX).
// Security issues are handled by the Semgrep rule packs; this config focuses on real bugs.
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

export default [
  { ignores: ["**/node_modules/**", "**/dist/**", "**/build/**", "**/*.min.js", "**/coverage/**"] },
  {
    files: ["**/*.{js,jsx,mjs,cjs}"],
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: { ...globals.node, ...globals.browser, ...globals.jest, ...globals.mocha },
    },
  },
  ...tseslint.configs.recommended.map((c) => ({ ...c, files: ["**/*.{ts,tsx}"] })),
  {
    files: ["**/*.{jsx,tsx,js}"],
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
    },
  },
  {
    rules: {
      "no-unused-vars": ["warn", { args: "none", ignoreRestSiblings: true }],
      "no-undef": "error",
      "no-unreachable": "error",
      "no-dupe-keys": "error",
      "no-self-compare": "error",
      "no-unsafe-finally": "error",
      "no-constant-condition": "warn",
      "no-async-promise-executor": "error",
      "no-await-in-loop": "warn",
      "no-promise-executor-return": "error",
      "require-atomic-updates": "warn",
      "eqeqeq": ["warn", "smart"],
      "no-fallthrough": "warn",
      "array-callback-return": "error",
    },
  },
];
