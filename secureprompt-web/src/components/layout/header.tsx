"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { signOut } from "next-auth/react";
import { ChevronsUpDown, LogOut, Menu, Moon, Sun, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Separator } from "@/components/ui/separator";

interface HeaderProps {
  onToggleSidebar: () => void;
  workspaceId: string;
}

export function Header({ onToggleSidebar, workspaceId }: HeaderProps) {
  const router = useRouter();
  const [theme, setTheme] = useState<"light" | "dark">("light");

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
        <Button variant="ghost" size="icon" onClick={onToggleSidebar} aria-label="Toggle sidebar">
          <Menu className="size-4" />
        </Button>
        <Separator orientation="vertical" className="h-4" />
      </div>

      <div className="ml-auto flex items-center gap-2">
        <span className="hidden rounded-md border border-border px-2.5 py-1 font-mono text-xs text-muted-foreground md:inline">
          ws:{workspaceId.slice(0, 8)}
        </span>

        <Button variant="outline" size="icon" onClick={toggleTheme} aria-label="Toggle theme">
          {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="gap-2 px-2">
              <Avatar className="size-8">
                <AvatarFallback className="bg-secondary text-secondary-foreground">
                  <User className="size-4" />
                </AvatarFallback>
              </Avatar>
              <span className="hidden text-sm md:inline">Account</span>
              <ChevronsUpDown className="hidden size-4 text-muted-foreground md:inline" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-44">
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => { void handleLogout(); }}
              className="cursor-pointer gap-2 text-destructive hover:text-destructive"
            >
              <LogOut className="size-4" />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
