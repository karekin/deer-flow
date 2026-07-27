import { expect, test } from "@rstest/core";

import { displayNameOfAgent } from "@/core/agents/utils";

test("uses the human-readable agent name when configured", () => {
  expect(
    displayNameOfAgent({
      name: "cloudmold-inventory-control-agent",
      display_name: "库控Agent",
    }),
  ).toBe("库控Agent");
});

test("falls back to the stable agent identifier for missing or blank display names", () => {
  expect(displayNameOfAgent({ name: "researcher", display_name: null })).toBe(
    "researcher",
  );
  expect(displayNameOfAgent({ name: "researcher", display_name: "  " })).toBe(
    "researcher",
  );
});
