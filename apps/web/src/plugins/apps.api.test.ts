import { describe, expect, it } from "vitest";
// @ts-ignore -- Vitest runs in Node; this app intentionally omits Node typings.
import { readFileSync } from "node:fs";

import * as api from "../../../../vendor/systutor-core/plugins/apps/frontend/api";

describe("Apps API module contract", () => {
  it("exports the installation repositories reader used by the UI", () => {
    expect(typeof api.listInstallationRepositories).toBe("function");
    expect("listRepositories" in api).toBe(false);
  });

  it("keeps repository query keys installation-scoped", () => {
    expect(api.appsKeys.repositories("installation-1")).toEqual([
      "apps", "github", "installations", "installation-1", "repositories",
    ]);
    expect(api.appsKeys.repositories("installation-2")).not.toEqual(
      api.appsKeys.repositories("installation-1"),
    );
  });

  it("keeps accepted operations polling until they are terminal", () => {
    const page = readFileSync(new URL(
      "../../../../vendor/systutor-core/plugins/apps/frontend/pages/AppsPage.tsx",
      import.meta.url,
    ), "utf8");
    // The watcher must survive the detail dialog closing, so it lives at page
    // level and invalidates the app queries when the operation finishes.
    expect(page).toContain("OperationWatcher");
    expect(page).toMatch(/tracked\.map\(\(operation\)/);
  });

  it("creates applications without compose or ingress overrides", () => {
    const dialog = readFileSync(new URL(
      "../../../../vendor/systutor-core/plugins/apps/frontend/components/CreateApplicationDialog.tsx",
      import.meta.url,
    ), "utf8");
    expect(dialog).not.toContain("Compose (optional");
    expect(dialog).not.toContain("Platform ingress");
  });
});
