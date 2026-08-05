"use client";

/**
 * Entity-type picker used by the tokenize playground.
 *
 * The backend's POST /v1/secure-mode/tokenize accepts an optional
 * `entity_labels: string[]` that filters which PII types get redacted.
 * When the list is empty OR equals the full universe, we send `undefined`
 * so the backend applies its default (all types).
 */

import { useMemo } from "react";
import { useTranslations } from "next-intl";
import { Label } from "@/components/ui/label";

export interface EntityGroup {
  title: string;
  items: { value: string; label: string }[];
}

export const ENTITY_GROUPS: EntityGroup[] = [
  {
    title: "Core identity",
    items: [
      { value: "PERSON", label: "Person" },
      { value: "ORGANIZATION", label: "Organization" },
      { value: "ADDRESS", label: "Address" },
    ],
  },
  {
    title: "Contact",
    items: [
      { value: "EMAIL_ADDRESS", label: "Email" },
      { value: "PHONE_NUMBER", label: "Phone" },
      { value: "URL", label: "URL" },
      { value: "SOCIAL_HANDLE", label: "Social handle" },
      { value: "USERNAME", label: "Username" },
    ],
  },
  {
    title: "Financial",
    items: [
      { value: "CREDIT_CARD", label: "Credit card" },
      { value: "CREDIT_CARD_CVV", label: "CVV / CVC" },
      { value: "IBAN_CODE", label: "IBAN" },
      { value: "BANK_ACCOUNT", label: "Bank account" },
    ],
  },
  {
    title: "Government ID",
    items: [
      { value: "US_SSN", label: "SSN" },
      { value: "PASSPORT_NUMBER", label: "Passport" },
      { value: "DRIVER_LICENSE", label: "Driver's license" },
      { value: "NATIONAL_ID", label: "National ID" },
      { value: "ID_CARD", label: "ID card" },
      { value: "TAX_ID", label: "Tax ID" },
    ],
  },
  {
    title: "Medical",
    items: [
      { value: "MEDICAL_LICENSE", label: "Medical license" },
      { value: "HEALTH_INSURANCE_ID", label: "Health insurance ID" },
    ],
  },
  {
    title: "Network",
    items: [{ value: "IP_ADDRESS", label: "IP address" }],
  },
  {
    title: "Misc",
    items: [{ value: "POSTAL_CODE", label: "Postal code" }],
  },
];

export const ALL_ENTITY_VALUES: string[] = ENTITY_GROUPS.flatMap((g) =>
  g.items.map((i) => i.value),
);

interface Props {
  value: Set<string>;
  onChange: (next: Set<string>) => void;
  disabled?: boolean;
}

export function EntityPicker({ value, onChange, disabled }: Props) {
  const t = useTranslations("entityPicker");
  const totalSelected = value.size;
  const total = ALL_ENTITY_VALUES.length;

  const toggle = (v: string) => {
    const next = new Set(value);
    if (next.has(v)) next.delete(v);
    else next.add(v);
    onChange(next);
  };

  const selectAll = () => onChange(new Set(ALL_ENTITY_VALUES));
  const selectNone = () => onChange(new Set());

  const summary = useMemo(() => {
    if (totalSelected === 0) return t("summaryNone");
    if (totalSelected === total) return t("summaryAll");
    return t("summarySome", { selected: totalSelected, total });
  }, [t, totalSelected, total]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <Label className="text-sm font-medium">{t("title")}</Label>
          <p className="text-xs text-muted-foreground">{summary}</p>
        </div>
        <div className="flex gap-2 text-xs">
          <button
            type="button"
            onClick={selectAll}
            disabled={disabled}
            className="underline text-muted-foreground hover:text-foreground disabled:opacity-50"
          >
            {t("selectAll")}
          </button>
          <span className="text-muted-foreground">·</span>
          <button
            type="button"
            onClick={selectNone}
            disabled={disabled}
            className="underline text-muted-foreground hover:text-foreground disabled:opacity-50"
          >
            {t("clear")}
          </button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {ENTITY_GROUPS.map((group) => (
          <fieldset
            key={group.title}
            disabled={disabled}
            className="rounded-md border p-3 space-y-2 disabled:opacity-60"
          >
            <legend className="text-xs font-medium text-muted-foreground px-1">
              {group.title}
            </legend>
            {group.items.map((item) => {
              const checked = value.has(item.value);
              return (
                <label
                  key={item.value}
                  className="flex items-center gap-2 text-sm cursor-pointer"
                >
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-input"
                    checked={checked}
                    onChange={() => toggle(item.value)}
                  />
                  <span>{item.label}</span>
                </label>
              );
            })}
          </fieldset>
        ))}
      </div>
    </div>
  );
}
