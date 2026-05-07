/**
 * Module augmentation for next-auth v5.
 * Keeps the Session / User / JWT shapes in lockstep with the Rust API's
 * TokenResponse contract (see secureprompt-schemas/openapi/v1/openapi.yaml).
 */
import type { DefaultSession, DefaultUser } from "next-auth";
import type { DefaultJWT } from "next-auth/jwt";

export type AppRole =
  | "owner"
  | "admin"
  | "developer"
  | "employee"
  | "viewer";

export interface AppSessionUser {
  id: string;
  email: string;
}

export interface AppSessionShape {
  user: AppSessionUser;
  workspaceId: string;
  role: AppRole;
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number; // unix seconds
  refreshExpiresAt: number; // unix seconds
  error?: "RefreshAccessTokenError";
}

declare module "next-auth" {
  interface Session extends AppSessionShape {
    // Keep default fields (expires) while overriding user with our narrow shape.
    user: AppSessionUser & DefaultSession["user"];
  }

  interface User extends DefaultUser {
    id: string;
    email: string;
    workspaceId: string;
    role: AppRole;
    accessToken: string;
    refreshToken: string;
    accessExpiresAt: number;
    refreshExpiresAt: number;
  }
}

declare module "next-auth/jwt" {
  interface JWT extends DefaultJWT {
    user: AppSessionUser;
    workspaceId: string;
    role: AppRole;
    accessToken: string;
    refreshToken: string;
    accessExpiresAt: number;
    refreshExpiresAt: number;
    error?: "RefreshAccessTokenError";
  }
}
