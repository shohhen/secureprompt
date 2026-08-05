"use client";

/**
 * Phase 1 / 2FA Console — TwoFactorQr
 *
 * Thin wrapper over `qrcode.react`'s `QRCodeSVG`. Renders an `otpauth://`
 * provisioning URI as a scannable QR code for the 2FA enrollment screen.
 *
 * Props:
 *   value — the otpauth:// provisioning URI (from POST /v1/auth/2fa/enroll)
 */

import { QRCodeSVG } from "qrcode.react";
import { useTranslations } from "next-intl";

export function TwoFactorQr({ value }: { value: string }) {
  const t = useTranslations("twoFactor");
  return (
    <div className="flex justify-center rounded-lg border bg-white p-4">
      <QRCodeSVG value={value} size={192} includeMargin aria-label={t("qrAlt")} />
    </div>
  );
}
