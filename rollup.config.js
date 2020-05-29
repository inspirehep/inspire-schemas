import pkg from './package.json';
import json from '@rollup/plugin-json';

export default {
  input: 'js/index.js',
  output: [
    {
      file: pkg.main,
      format: 'cjs'
    },
    {
      file: pkg.module,
      format: 'es',
      sourcemap: true
    }
],
  plugins: [ json() ]
};
