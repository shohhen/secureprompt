"use client";

/**
 * TanStack Query hooks for /v1/users (workspace members).
 *
 * GET — any authenticated role; lists members in the caller's workspace.
 * POST — admin-only on the backend. The dashboard disables the invite form
 *        when `session.role` is not admin/owner.
 *
 * WS6-4: on the generated client. `role` is now the generated union, which is
 * five variants (`owner|admin|developer|employee|viewer`) — the spec omitted
 * `employee` until this workstream.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { makeApiClient, unwrap, type ApiError } from "@/lib/api-client";
import type { components } from "@/types/api.gen";

export type UserResponse = components["schemas"]["UserResponse"];
export type CreateUserBody = components["schemas"]["CreateUserRequest"];

export function useUsers() {
  return useQuery<UserResponse[], ApiError>({
    queryKey: ["users"],
    queryFn: () => unwrap(makeApiClient().GET("/v1/users")),
  });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation<UserResponse, ApiError, CreateUserBody>({
    mutationFn: (body) => unwrap(makeApiClient().POST("/v1/users", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
}
