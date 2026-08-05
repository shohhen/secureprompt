"use client";

/**
 * /v1/me/profile — read + update the authenticated caller's profile.
 *
 * Display logic: when a user hasn't filled in their name yet, the
 * backend returns `display_name = email-local-part` so the sidebar
 * still has something useful to render.
 *
 * WS6-4: on the generated client. The hand-written `MyProfile` was missing
 * `device_mac`, which the handler has returned since the desktop wrapper
 * landed.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { makeApiClient, unwrap, type ApiError } from "@/lib/api-client";
import type { components } from "@/types/api.gen";

export type MyProfile = components["schemas"]["MyProfile"];
export type UpdateMyProfile = components["schemas"]["UpdateProfileRequest"];

export function useMyProfile() {
  return useQuery<MyProfile, ApiError>({
    queryKey: ["me-profile"],
    queryFn: () => unwrap(makeApiClient().GET("/v1/me/profile")),
    staleTime: 60_000,
  });
}

export function useUpdateMyProfile() {
  const qc = useQueryClient();
  return useMutation<MyProfile, ApiError, UpdateMyProfile>({
    mutationFn: (body) =>
      unwrap(makeApiClient().PUT("/v1/me/profile", { body })),
    onSuccess: (data) => {
      qc.setQueryData(["me-profile"], data);
    },
  });
}
