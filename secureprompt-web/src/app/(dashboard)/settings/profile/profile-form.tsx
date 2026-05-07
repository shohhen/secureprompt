"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { useMyProfile, useUpdateMyProfile } from "@/lib/hooks/use-profile";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";

export function ProfileForm() {
  const { data, isLoading, error } = useMyProfile();
  const update = useUpdateMyProfile();

  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [position, setPosition] = useState("");

  // Hydrate from server response. Empty server values render as empty
  // strings (controlled input) — saving them back becomes NULL on the
  // server (the handler trims+filters), so the round-trip is stable.
  useEffect(() => {
    if (data) {
      setFirstName(data.first_name ?? "");
      setLastName(data.last_name ?? "");
      setPosition(data.position ?? "");
    }
  }, [data]);

  if (isLoading) {
    return (
      <div className="space-y-3 max-w-lg">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <p className="text-sm text-destructive">
        Failed to load profile: {error.message}
      </p>
    );
  }

  if (!data) return null;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    try {
      await update.mutateAsync({
        first_name: firstName,
        last_name: lastName,
        position,
      });
      toast.success("Profile updated.");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Update failed.");
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-6 max-w-lg">
      <div className="rounded-lg border p-5 space-y-4">
        <ReadOnlyField label="Email" value={data.email} mono />
        <ReadOnlyField label="Role" value={data.role} />
      </div>

      <div className="rounded-lg border p-5 space-y-4">
        <FieldRow
          id="first_name"
          label="First name"
          value={firstName}
          onChange={setFirstName}
        />
        <FieldRow
          id="last_name"
          label="Last name"
          value={lastName}
          onChange={setLastName}
        />
        <FieldRow
          id="position"
          label="Position / job title"
          value={position}
          onChange={setPosition}
          placeholder="e.g. Backend Engineer"
        />
      </div>

      <div className="flex justify-end">
        <Button type="submit" size="sm" disabled={update.isPending}>
          {update.isPending ? "Saving…" : "Save"}
        </Button>
      </div>
    </form>
  );
}

function ReadOnlyField({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="space-y-1">
      <Label className="text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </Label>
      <p className={mono ? "font-mono text-sm" : "text-sm"}>{value}</p>
    </div>
  );
}

function FieldRow({
  id,
  label,
  value,
  onChange,
  placeholder,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
    </div>
  );
}
