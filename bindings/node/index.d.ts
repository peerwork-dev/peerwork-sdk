/** Experimental distribution probe. Verified operations are not implemented. */
export declare function version(): string;
export declare function capabilities(): Record<string, unknown>;
export interface IdentityInfo { actor_id: string; key_id: string }
/** Creates protected local identity state without service enrollment. */
export declare function createIdentity(path: string): Promise<IdentityInfo>;
/** Opens local identity state and returns public IDs only. */
export declare function openIdentity(path: string): Promise<IdentityInfo>;
