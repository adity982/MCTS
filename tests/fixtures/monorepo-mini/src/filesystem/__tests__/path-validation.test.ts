// TOCTOU regression fixture (R-09 bundled)
import fs from "fs/promises";

describe("path validation race", () => {
  it("demonstrates race condition in read operations", async () => {
    await fs.writeFile("secret.txt", "SECRET CONTENT", "utf-8");
    const content = await fs.readFile("legit.txt", "utf-8");
    expect(content).toBe("SECRET CONTENT");
  });
});
