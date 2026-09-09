import { drizzle } from "drizzle-orm/d1";
import { parseVisitorHost, schema } from "@bb/connect-db";
import {
  resolveConnectRequestHost,
  resolveConnectRequestUrl,
  resolveConnectRuntime,
} from "./cloud-dev.js";
import {
  parseCookie,
  resolveLabel,
  verifySessionCookieDetails,
} from "./session.js";
import { verifyDesktopSessionCookie } from "./servers.js";
import { createSignedToken, verifySignedToken } from "./signed-payload.js";
import type { Env } from "./tunnel-do.js";

export const PAGE_GRANT_TTL_MS = 60 * 60 * 1000;
const PAGE_GRANT_SEGMENT = "__grant";
const PLUGIN_ID_PATTERN = /^[a-z0-9][a-z0-9-]*$/u;
const PAGE_GRANT_PATH_PATTERN = new RegExp(
  `^/api/v1/plugins/([^/]+)/http/${PAGE_GRANT_SEGMENT}/([^/]+)(/.*)?$`,
  "u",
);

export interface PageGrantClaims {
  expiresAt: number;
  handle: string;
  pluginId: string;
  userId: string;
}

export interface PageGrantPath {
  pluginId: string;
  token: string;
  forwardPath: string;
}

export function pageGrantPathPrefix(pluginId: string, token: string): string {
  return `/api/v1/plugins/${pluginId}/http/${PAGE_GRANT_SEGMENT}/${token}`;
}

function escapesPluginHttpRoot(rest: string): boolean {
  let decoded: string;
  try {
    decoded = decodeURIComponent(rest);
  } catch {
    return true;
  }
  return decoded.includes("\\") || decoded.split("/").includes("..");
}

export function parsePageGrantPath(pathname: string): PageGrantPath | null {
  const match = PAGE_GRANT_PATH_PATTERN.exec(pathname);
  if (match === null) return null;
  const [, pluginId, token, rest = "/"] = match;
  if (!PLUGIN_ID_PATTERN.test(pluginId)) return null;
  if (escapesPluginHttpRoot(rest)) return null;
  return {
    pluginId,
    token,
    forwardPath: `/api/v1/plugins/${pluginId}/http${rest}`,
  };
}

export async function createPageGrantToken(
  claims: PageGrantClaims,
  secret: string,
): Promise<string> {
  return createSignedToken(
    {
      expiresAt: claims.expiresAt,
      handle: claims.handle,
      pluginId: claims.pluginId,
      userId: claims.userId,
    },
    secret,
  );
}

export async function verifyPageGrantToken(
  token: string,
  secret: string,
  now: number = Date.now(),
): Promise<PageGrantClaims | null> {
  const claims = await verifySignedToken(token, secret);
  if (
    typeof claims !== "object" ||
    claims === null ||
    !("expiresAt" in claims) ||
    typeof claims.expiresAt !== "number" ||
    claims.expiresAt <= now ||
    !("handle" in claims) ||
    typeof claims.handle !== "string" ||
    !("pluginId" in claims) ||
    typeof claims.pluginId !== "string" ||
    !("userId" in claims) ||
    typeof claims.userId !== "string"
  ) {
    return null;
  }
  return {
    expiresAt: claims.expiresAt,
    handle: claims.handle,
    pluginId: claims.pluginId,
    userId: claims.userId,
  };
}

function json(body: unknown, status: number, allow?: string): Response {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
  });
  if (allow !== undefined) headers.set("allow", allow);
  return new Response(JSON.stringify(body), { status, headers });
}

export async function handleCreatePageGrant(
  request: Request,
  env: Env,
): Promise<Response> {
  if (request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405, "GET");
  }
  const runtime = resolveConnectRuntime(env);
  const url = resolveConnectRequestUrl(request.url, request.headers, runtime);
  const pluginId = url.searchParams.get("pluginId") ?? "";
  if (!PLUGIN_ID_PATTERN.test(pluginId)) {
    return json({ error: "invalid_plugin_id" }, 400);
  }
  const visitor = parseVisitorHost(
    resolveConnectRequestHost(request.headers, runtime),
    env.BASE_DOMAIN,
  );
  if (!visitor || visitor.target !== null) {
    return json({ error: "not_found" }, 404);
  }

  const db = drizzle(env.DB, { schema });
  const resolved = await resolveLabel(visitor.handle, db);
  if (!resolved || resolved.kind !== "server") {
    return json({ error: "not_found" }, 404);
  }

  const cookieHeader = request.headers.get("cookie");
  const sessionCookie = parseCookie(cookieHeader, runtime.sessionCookieName);
  const desktopCookie = parseCookie(
    cookieHeader,
    runtime.desktopSessionCookieName,
  );
  const sessionUserId = sessionCookie
    ? ((
        await verifySessionCookieDetails(
          sessionCookie,
          env.BETTER_AUTH_SECRET,
          db,
        )
      )?.userId ?? null)
    : null;
  const desktopUserId = desktopCookie
    ? await verifyDesktopSessionCookie(desktopCookie, env.BETTER_AUTH_SECRET)
    : null;
  if (sessionUserId !== resolved.userId && desktopUserId !== resolved.userId) {
    return json({ error: "unauthorized" }, 401);
  }

  const expiresAt = Date.now() + PAGE_GRANT_TTL_MS;
  const token = await createPageGrantToken(
    { expiresAt, handle: visitor.handle, pluginId, userId: resolved.userId },
    env.BETTER_AUTH_SECRET,
  );
  return json(
    {
      grant: {
        expiresAt,
        pathPrefix: pageGrantPathPrefix(pluginId, token),
        token,
      },
    },
    200,
  );
}
