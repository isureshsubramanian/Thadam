// Lint rules (ADR-008 Decision 13; global React rules): strict TypeScript, no `any`, no raw
// HTML from data, and hooks called by the rules with every dependency listed.
// `dangerouslySetInnerHTML` is banned with core ESLint's no-restricted-syntax.
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "node_modules/", "eslint.config.js"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      // useApi and usePaged take a load function and its deps, as useEffect does.
      "react-hooks/exhaustive-deps": ["error", { additionalHooks: "^(useApi|usePaged)$" }],
      "@typescript-eslint/no-explicit-any": "error",
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Store values are shown as text only (ADR-008 Decision 3).",
        },
        {
          selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]",
          message: "Store values are shown as text only (ADR-008 Decision 3).",
        },
      ],
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
    },
  },
);
