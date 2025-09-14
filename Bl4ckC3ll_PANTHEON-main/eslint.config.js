// Modern ESLint configuration for Bl4ckC3ll_PANTHEON V2.0.0
import js from '@eslint/js';
import security from 'eslint-plugin-security';
import node from 'eslint-plugin-node';

export default [
  js.configs.recommended,
  security.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: {
        node: true,
        process: true,
        console: true,
        Buffer: true,
        __dirname: true,
        __filename: true,
        global: true,
        module: true,
        require: true,
        exports: true
      }
    },
    plugins: {
      security,
      node
    },
    rules: {
      // Security rules
      'security/detect-object-injection': 'error',
      'security/detect-non-literal-regexp': 'error',
      'security/detect-unsafe-regex': 'error',
      'security/detect-buffer-noassert': 'error',
      'security/detect-child-process': 'error',
      'security/detect-disable-mustache-escape': 'error',
      'security/detect-eval-with-expression': 'error',
      'security/detect-no-csrf-before-method-override': 'error',
      'security/detect-non-literal-fs-filename': 'error',
      'security/detect-non-literal-require': 'error',
      'security/detect-possible-timing-attacks': 'error',
      'security/detect-pseudoRandomBytes': 'error',

      // Code quality rules
      'no-unused-vars': 'error',
      'no-console': 'warn',
      'prefer-const': 'error',
      'no-var': 'error',
      'eqeqeq': 'error',
      'curly': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error'
    },
    ignores: [
      'node_modules/**',
      'dist/**', 
      'build/**',
      'logs/**',
      'runs/**',
      '*.min.js',
      'package-lock.json'
    ]
  }
];