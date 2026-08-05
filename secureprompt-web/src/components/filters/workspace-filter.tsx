"use client";

/**
 * Phase 5 / Plan 05-03 — Workspace selector filter.
 *
 * In MVP the workspace is fixed to the session workspaceId, so this component
 * renders a read-only badge rather than a dropdown. It is still a dedicated
 * component so future plans can swap in multi-workspace select without
 * touching the page files.
 */

interface WorkspaceFilterProps {
  workspaceId: string;
}

export function WorkspaceFilter({ workspaceId }: WorkspaceFilterProps) {
  const t = useTranslations("filters");
  return (
    <div className="flex items-center gap-2">
      <span className="text-sm font-medium text-foreground/80">{t("workspace")}</span>
      <span className="rounded bg-muted px-2 py-1 font-mono text-xs">
        {workspaceId.slice(0, 8)}…
      </span>
    </div>
  );
}
