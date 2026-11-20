import { constants } from 'node:fs';
import { access } from 'node:fs/promises';
import { homedir } from 'node:os';
import { delimiter, dirname, isAbsolute, join } from 'node:path';
import { z } from 'zod';
import {
  PasswordManagerError,
  type PasswordManager,
  type PasswordManagerLogin,
} from '../../ports/password-manager.ts';
import { matchingWebsite } from '../password-manager-websites.ts';
import { runProcess, RuntimeTimeLimitError } from '../process.ts';

const inherited = [
  'HOME',
  'USERPROFILE',
  'APPDATA',
  'LOCALAPPDATA',
  'SystemRoot',
  'TMPDIR',
  'TEMP',
  'TMP',
  'LANG',
  'XDG_CONFIG_HOME',
  'BITWARDENCLI_APPDATA_DIR',
];

const itemId = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);

const item = z.object({
  id: z.string(),
  name: z.string(),
  type: z.number(),
  deletedDate: z.string().nullish(),
  archivedDate: z.string().nullish(),
  login: z
    .object({
      username: z.string().nullish(),
      password: z.string().nullish(),
      totp: z.string().nullish(),
      uris: z.array(z.object({ uri: z.string().nullish(), match: z.number().nullish() })).nullish(),
    })
    .nullish(),
});

const status = z.object({
  status: z.string(),
  userEmail: z.string().nullish(),
});

type Item = z.infer<typeof item>;

function behavior(match: number | null | undefined) {
  if (match === null || match === undefined || match === 0) return 'AnywhereOnWebsite';
  return match <= 3 ? 'ExactDomain' : 'Never';
}

function website(entry: Item, origin: string) {
  if (
    entry.type !== 1 ||
    entry.deletedDate ||
    entry.archivedDate ||
    !itemId.safeParse(entry.id).success
  )
    return undefined;
  return matchingWebsite(
    (entry.login?.uris ?? []).flatMap(({ uri, match }) =>
      uri ? [{ url: uri, autofillBehavior: behavior(match) }] : [],
    ),
    origin,
  );
}

function folders() {
  const home = homedir();
  const listed = (process.env.PATH ?? '').split(delimiter);
  if (process.platform === 'win32')
    return [
      ...listed,
      join(process.env.LOCALAPPDATA ?? '', 'Microsoft', 'WinGet', 'Links'),
      join(home, 'scoop', 'shims'),
      'C:\\ProgramData\\chocolatey\\bin',
    ];
  return [
    ...listed,
    '/opt/homebrew/bin',
    '/usr/local/bin',
    '/snap/bin',
    join(home, '.local', 'bin'),
    join(home, '.npm-global', 'bin'),
  ];
}

async function findBitwardenCommand() {
  const name = process.platform === 'win32' ? 'bw.exe' : 'bw';
  for (const folder of folders()) {
    if (!folder || !isAbsolute(folder)) continue;
    const path = join(folder, name);
    try {
      await access(path, constants.X_OK);
      return path;
    } catch {}
  }
  return undefined;
}

export function createBitwarden(
  options: { command?: () => Promise<string | undefined>; idleMs?: number } = {},
): PasswordManager {
  const locate = options.command ?? findBitwardenCommand;
  const idleMs = options.idleMs ?? 5 * 60_000;
  let session: { command: string; account: string; key: string; timer: NodeJS.Timeout } | undefined;
  let queue: Promise<unknown> = Promise.resolve();

  function serial<T>(run: () => Promise<T>) {
    const next = queue.then(run, run);
    queue = next.catch(() => {});
    return next;
  }

  async function bw(
    command: string,
    args: string[],
    extra: Record<string, string>,
    signal?: AbortSignal,
  ) {
    const env: NodeJS.ProcessEnv = Object.fromEntries(
      inherited.flatMap((name) => (process.env[name] ? [[name, process.env[name]]] : [])),
    );
    env.PATH = [dirname(command), process.env.PATH].filter(Boolean).join(delimiter);
    const result = await runProcess(command, ['--nointeraction', ...args], {
      env: { ...env, ...extra },
      signal,
      timeoutMs: 60_000,
    }).catch((error: unknown) => {
      if (error instanceof RuntimeTimeLimitError)
        throw new PasswordManagerError('failed', 'Bitwarden didn’t answer in time.');
      if (signal?.aborted)
        throw new PasswordManagerError('failed', 'The Bitwarden request was cancelled.');
      throw new PasswordManagerError('unavailable', 'Bitwarden: the bw command couldn’t start.');
    });
    if (result.exitCode === 0) return result.stdout;
    let message = (
      result.stderr.trim() ||
      result.stdout.trim() ||
      `bw exited with ${result.exitCode}`
    ).replace(/\s+/g, ' ');
    for (const secret of Object.values(extra))
      if (secret) message = message.split(secret).join('[hidden]');
    throw new PasswordManagerError('failed', `Bitwarden: ${message.slice(0, 300)}`);
  }

  function parse<T>(schema: z.ZodType<T>, output: string) {
    try {
      return schema.parse(JSON.parse(output));
    } catch {
      throw new PasswordManagerError('failed', 'Bitwarden sent an unexpected answer.');
    }
  }

  async function lock() {
    const current = session;
    session = undefined;
    if (!current) return;
    clearTimeout(current.timer);
    await bw(current.command, ['lock'], { BW_SESSION: current.key }).catch(() => {});
  }

  async function unlock(account: string, masterPassword: string, signal?: AbortSignal) {
    await lock();
    const command = await locate();
    if (!command)
      throw new PasswordManagerError('unavailable', 'Bitwarden: the bw command wasn’t found.');
    const current = parse(status, await bw(command, ['status'], {}, signal));
    if (current.status === 'unauthenticated' || !current.userEmail)
      throw new PasswordManagerError(
        'unavailable',
        'Bitwarden: the Bitwarden CLI on this computer isn’t signed in.',
      );
    if (current.userEmail.trim().toLowerCase() !== account)
      throw new PasswordManagerError(
        'missing',
        'The Bitwarden CLI on this computer is signed in to a different account. Enter that account’s email, or run bw login with this one.',
      );
    const key = (
      await bw(
        command,
        ['unlock', '--passwordenv', 'BW_PASSWORD', '--raw'],
        {
          BW_PASSWORD: masterPassword,
        },
        signal,
      )
    ).trim();
    if (!key) throw new PasswordManagerError('failed', 'Bitwarden didn’t unlock.');
    const timer = setTimeout(() => void serial(lock), idleMs);
    timer.unref();
    session = { command, account, key, timer };
    return session;
  }

  return {
    id: 'bitwarden',
    name: 'Bitwarden',
    setup: 'Install the Bitwarden CLI (bw) and run bw login once in a terminal.',
    masterPassword: true,
    available: async () => Boolean(await locate()),
    logins: (account, origin, input) =>
      serial(async (): Promise<PasswordManagerLogin[]> => {
        if (!input?.masterPassword)
          throw new PasswordManagerError('missing', 'Enter your Bitwarden master password.');
        const current = await unlock(
          account.trim().toLowerCase(),
          input.masterPassword,
          input.signal,
        );
        try {
          await bw(current.command, ['sync'], { BW_SESSION: current.key }, input.signal);
          const items = parse(
            z.array(item),
            await bw(
              current.command,
              ['list', 'items', '--url', origin],
              { BW_SESSION: current.key },
              input.signal,
            ),
          );
          return items.flatMap((entry) => {
            const site = website(entry, origin);
            return site && entry.login?.password
              ? [
                  {
                    id: entry.id,
                    title: entry.name,
                    username: entry.login.username ?? '',
                    website: site,
                  },
                ]
              : [];
          });
        } catch (error) {
          await lock();
          throw error;
        }
      }),
    login: (account, origin, id, signal) =>
      serial(async () => {
        const current = session;
        try {
          if (!current || current.account !== account.trim().toLowerCase())
            throw new PasswordManagerError(
              'missing',
              'Bitwarden locked again. Enter your master password to choose a login.',
            );
          if (!itemId.safeParse(id).success)
            throw new PasswordManagerError(
              'missing',
              'This Bitwarden login is no longer available.',
            );
          const entry = parse(
            item,
            await bw(current.command, ['get', 'item', id], { BW_SESSION: current.key }, signal),
          );
          if (entry.id !== id || !website(entry, origin))
            throw new PasswordManagerError(
              'missing',
              'This Bitwarden login is not for this website.',
            );
          if (!entry.login?.password)
            throw new PasswordManagerError('missing', 'This Bitwarden login has no password.');
          return {
            title: entry.name,
            username: entry.login.username ?? '',
            password: entry.login.password,
            ...(entry.login.totp ? { authenticatorKey: entry.login.totp } : {}),
          };
        } finally {
          await lock();
        }
      }),
    close: () => serial(lock),
  };
}
