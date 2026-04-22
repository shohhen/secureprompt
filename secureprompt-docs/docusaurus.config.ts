import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

const config: Config = {
  title: "SecurePrompt Docs",
  tagline: "Security gateway for LLM applications",
  url: "https://docs.secureprompt.tech",
  baseUrl: "/",
  favicon: "img/favicon.ico",
  organizationName: "secureprompt",
  projectName: "secureprompt-docs",
  onBrokenLinks: "warn",
  i18n: { defaultLocale: "en", locales: ["en"] },
  presets: [
    [
      "classic",
      {
        docs: {
          routeBasePath: "/",
          sidebarPath: "./sidebars.ts",
        },
        blog: false,
        theme: { customCss: "./src/css/custom.css" },
      } satisfies Preset.Options,
    ],
  ],
  themeConfig: {
    navbar: {
      title: "SecurePrompt",
      items: [
        { type: "docSidebar", sidebarId: "docsSidebar", position: "left", label: "Docs" },
        { href: "http://localhost:3000", label: "Dashboard", position: "right" },
        { href: "https://github.com/secureprompt", label: "GitHub", position: "right" },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            { label: "Quickstart", to: "/getting-started/quickstart" },
            { label: "Security Deep Dive", to: "/concepts/security-deep-dive" },
            { label: "API Reference", to: "/api-reference/overview" },
          ],
        },
        {
          title: "Community",
          items: [
            { label: "GitHub", href: "https://github.com/secureprompt" },
          ],
        },
      ],
      copyright: `Copyright ${new Date().getFullYear()} SecurePrompt.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["bash", "python", "json", "rust"],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
