import type { AccountsStore } from '../domain/ports.js';
import { listScopesForAudience as impl } from './scope-catalog-impl.js';

/** Scope utilizzabili da un client registrato per quell'audience. */
export const listScopesForAudience: (store: AccountsStore, audience: string) => Promise<string[]> = impl;