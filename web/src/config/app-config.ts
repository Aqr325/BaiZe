import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "白泽",
  version: packageJson.version,
  copyright: `© ${currentYear}, 白泽.`,
  meta: {
    title: "白泽 — 自主渗透测试控制台",
    description: "白泽：LLM 驱动的自主渗透测试系统控制台",
  },
};
