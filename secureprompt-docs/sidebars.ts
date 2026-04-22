import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

const sidebars: SidebarsConfig = {
  docsSidebar: [
    { type: "doc", id: "index", label: "Introduction" },
    {
      type: "category",
      label: "Getting Started",
      collapsed: false,
      items: [
        "getting-started/quickstart",
        "getting-started/mcp-quickstart",
        "getting-started/configuration",
      ],
    },
    {
      type: "category",
      label: "Security",
      items: [
        "concepts/proxy",
        "concepts/policies",
        "concepts/secure-mode",
        "concepts/threat-protection",
        "concepts/security-deep-dive",
      ],
    },
    {
      type: "category",
      label: "Guides",
      items: [
        "guides/secure-mode",
        "guides/model-usage",
        "guides/compliance",
        "guides/self-hosting",
      ],
    },
    {
      type: "category",
      label: "API Reference",
      items: [
        "api-reference/overview",
        "api-reference/authentication",
        "api-reference/proxy",
        "api-reference/secure-mode",
        "api-reference/policies",
        "api-reference/providers",
        "api-reference/audit-logs",
        "api-reference/metrics",
        "api-reference/mcp",
      ],
    },
  ],
};

export default sidebars;
