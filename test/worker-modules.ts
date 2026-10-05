import { readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { V4ModuleDefinition } from 'miniflare';

export async function workerModules(): Promise<V4ModuleDefinition[]> {
  return [{ type: 'ESModule', path: resolve('dist/index.js') },
    ...(await readdir('dist')).filter(name=>name.endsWith('.txt')).map(name=>({type:'Text' as const,path:resolve('dist',name)})),
  ];
}
