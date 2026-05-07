"use client";

/**
 * /v1/me/profile — read + update the authenticated caller's profile.
 *
 * Display logic: when a user hasn't filled in their name yet, the
 * backend returns `display_name = email-local-part` so the sidebar
 * still has something useful to render.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

export interface MyProfile {
  user_id: string;
  workspace_id: string;
  email: string;
  role: string;
  first_name: string | null;
  last_name: string | null;
  position: string | null;
  display_name: string;
}

export interface UpdateMyProfile {
  first_name?: string | null;
  last_name?: string | null;
  position?: string | null;
}

export function useMyProfile() {
  return useQuery<MyProfile>({
    queryKey: ["me-profile"],
    queryFn: () => apiFetch<MyProfile>("/v1/me/profile"),
    staleTime: 60_000,
  });
}

export function useUpdateMyProfile() {
  const qc = useQueryClient();
  return useMutation<MyProfile, Error, UpdateMyProfile>({
    mutationFn: (body) =>
      apiFetch<MyProfile>("/v1/me/profile", { method: "PUT", body }),
    onSuccess: (data) => {
      qc.setQueryData(["me-profile"], data);
    },
  });
}
