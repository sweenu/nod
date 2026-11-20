import type { PasswordManagerLogin } from '../shared/contracts.ts';

export type { PasswordManagerLogin };

export interface PasswordManagerSecret {
  title: string;
  username: string;
  password: string;
  authenticatorKey?: string;
}

type PasswordManagerFailure = 'unavailable' | 'missing' | 'failed';

export class PasswordManagerError extends Error {
  constructor(
    readonly reason: PasswordManagerFailure,
    message: string,
  ) {
    super(message);
  }
}

export interface PasswordManager {
  readonly id: string;
  readonly name: string;
  readonly setup: string;
  readonly masterPassword?: boolean;
  available?(): Promise<boolean>;
  logins(
    account: string,
    origin: string,
    options?: { masterPassword?: string; signal?: AbortSignal },
  ): Promise<PasswordManagerLogin[]>;
  login(
    account: string,
    origin: string,
    id: string,
    signal?: AbortSignal,
  ): Promise<PasswordManagerSecret>;
  close(): Promise<void>;
}
