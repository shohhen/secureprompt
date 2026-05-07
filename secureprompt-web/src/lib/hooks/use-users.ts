"use client";

/**
 * TanStack Query hooks for /v1/users (workspace members).
 *
 * GET — any authenticated role; lists members in the caller's workspace.
 * POST — admin-only on the backend. The dashboard disables the invite form
 *        when `session.role` is not admin/owner.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";
import type { AppRole } from "@/types/next-auth";

export interface UserResponse {
  id: string;
  workspace_id: string;
  email: string;
  role: AppRole;
  created_at: string;
  updated_at: string;
}

export interface CreateUserBody {
  email: string;
  password: string;
  role: AppRole;
}

export function useUsers() {
  return useQuery<UserResponse[]>({
    queryKey: ["users"],
    queryFn: () => apiFetch<UserResponse[]>("/v1/users"),
  });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation<UserResponse, Error, CreateUserBody>({
    mutationFn: (body) =>
      apiFetch<UserResponse>("/v1/users", { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
}
