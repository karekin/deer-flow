import type { Agent } from "./types";

export function displayNameOfAgent(
  agent: Pick<Agent, "name" | "display_name">,
): string {
  const configuredName = agent.display_name?.trim();
  if (!configuredName) {
    return agent.name;
  }
  return configuredName;
}
