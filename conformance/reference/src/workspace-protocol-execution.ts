import type {Manifest} from './workspace-manifest.js';

/** Call only after schema validation and exact dependency composition. */
export function requireExecutableProtocol(manifest:Manifest):void{
 if(manifest.execution_requirements?.ports.some(port=>port.required&&!port.bound))throw new Error('COMPOSITION_CONFLICT');
}
