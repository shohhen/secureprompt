"use client";

import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { signOut } from "next-auth/react";
import { ChevronsUpDown, LogOut, Menu, Moon, Sun, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Separator } from "@/components/ui/separator";
import { useMyProfile } from "@/lib/hooks/use-profile";
import { LocaleSwitcher } from "@/components/layout/locale-switcher";

interface HeaderProps {
  onToggleSidebar: () => void;
  workspaceId: string;
}

export function Header({ onToggleSidebar, workspaceId }: HeaderProps) {
  const router = useRouter();
  const t = useTranslations("header");
  const [theme, setTheme] = useState<"light" | "dark">("light");
  const { data: profile } = useMyProfile();
  const displayName = profile?.display_name ?? t("account");
  const initials = profile
    ? (profile.first_name?.[0] ?? profile.email[0] ?? "U") +
      (profile.last_name?.[0] ?? "")
    : null;

  useEffect(() => {
    const saved = window.localStorage.getItem("sp_theme");
    const preferred = saved ?? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    applyTheme(preferred as "light" | "dark");
    setTheme(preferred as "light" | "dark");
  }, []);

  function applyTheme(t: "light" | "dark") {
    document.documentElement.classList.toggle("dark", t === "dark");
    document.documentElement.style.colorScheme = t;
    window.localStorage.setItem("sp_theme", t);
  }

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    applyTheme(next);
    setTheme(next);
  };

  const handleLogout = async () => {
    await signOut({ redirect: false });
    router.replace("/login");
    router.refresh();
  };

  return (
    <header className="flex h-14 shrink-0 items-center gap-2 border-b border-border/80 px-3 md:px-4">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="icon" onClick={onToggleSidebar} aria-label={t("toggleSidebar")}>
          <Menu className="size-4" />
        </Button>
        <Separator orientation="vertical" className="h-4" />
      </div>

      <div className="ml-auto flex items-center gap-2">
        <span className="hidden rounded-md border border-border px-2.5 py-1 font-mono text-xs text-muted-foreground md:inline">
          {/* i18n-exempt: "ws:" is an identifier prefix, not prose */}
          ws:{workspaceId.slice(0, 8)}
        </span>

        <LocaleSwitcher />

        <Button variant="outline" size="icon" onClick={toggleTheme} aria-label={t("toggleTheme")}>
          {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="gap-2 px-2">
              <Avatar className="size-8">
                <AvatarFallback className="bg-secondary text-secondary-foreground">
                  {initials ? (
                    <span className="text-xs font-medium uppercase">
                      {initials}
                    </span>
                  ) : (
                    <User className="size-4" />
                  )}
                </AvatarFallback>
              </Avatar>
              <span className="hidden max-w-[12rem] truncate text-sm md:inline">
                {displayName}
              </span>
              <ChevronsUpDown className="hidden size-4 text-muted-foreground md:inline" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-60">
            {profile && (
              <DropdownMenuLabel className="font-normal">
                <div className="flex flex-col gap-0.5">
                  <span className="text-sm font-medium">
                    {profile.display_name}
                  </span>
                  <span className="truncate text-xs text-muted-foreground">
                    {profile.email}
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    {t("role", { role: profile.role })}
                    {profile.position ? ` · ${profile.position}` : ""}
                  </span>
                </div>
              </DropdownMenuLabel>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => router.push("/settings/profile")}
              className="cursor-pointer gap-2"
            >
              <User className="size-4" />
              {t("profile")}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => { void handleLogout(); }}
              className="cursor-pointer gap-2 text-destructive hover:text-destructive"
            >
              <LogOut className="size-4" />
              {t("signOut")}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
