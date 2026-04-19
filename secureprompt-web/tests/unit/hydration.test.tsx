/**
 * VALIDATION 5-02-01 — TanStack Query v5 RSC hydration round-trip.
 *
 * Seeds a query client on the "server", dehydrates, re-hydrates on the
 * "client" via <HydrationBoundary>, and asserts:
 *   1. The Consumer renders the seeded value on first render.
 *   2. No network fetch was made (dehydrated data short-circuits the fetch).
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import {
  QueryClient,
  QueryClientProvider,
  HydrationBoundary,
  dehydrate,
  useQuery,
} from "@tanstack/react-query";

const PROBE_KEY = ["probe"] as const;

function Consumer() {
  const { data } = useQuery({
    queryKey: PROBE_KEY,
    queryFn: async () => {
      // If hydration worked, this is never called.
      const res = await fetch("/should-not-be-called");
      return res.json() as Promise<{ value: number }>;
    },
    // Keep the seeded data fresh for the duration of the test so the query
    // is not considered stale (which would schedule a background refetch).
    staleTime: Infinity,
  });
  return <div data-testid="probe-value">{data?.value ?? "missing"}</div>;
}

describe("TanStack Query RSC hydration", () => {
  it("renders seeded data on first paint without fetching", async () => {
    // "Server": create a client, seed a value, dehydrate.
    const serverClient = new QueryClient();
    serverClient.setQueryData(PROBE_KEY, { value: 42 });
    const state = dehydrate(serverClient);

    // Spy on global fetch — must not be called.
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(() => {
      throw new Error("fetch called during hydrated render — hydration broken");
    });

    // "Client": fresh QueryClient + HydrationBoundary.
    const clientQueryClient = new QueryClient();

    render(
      <QueryClientProvider client={clientQueryClient}>
        <HydrationBoundary state={state}>
          <Consumer />
        </HydrationBoundary>
      </QueryClientProvider>,
    );

    const node = await screen.findByTestId("probe-value");
    expect(node.textContent).toBe("42");
    expect(fetchSpy).not.toHaveBeenCalled();

    fetchSpy.mockRestore();
  });
});
