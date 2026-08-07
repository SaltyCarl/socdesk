module.exports = {
  testDir: "./specs", retries: 0, reporter: "line",
  use: {
    baseURL: "http://localhost:8123",
    // The page ships a strict CSP with no 'unsafe-eval'. Playwright's own
    // waitForFunction evaluates a string and is blocked by it — the policy
    // doing its job. App specs therefore bypass CSP to test BEHAVIOUR; the
    // policy itself is enforced and asserted in csp.spec.js, which opens its
    // own context with bypassCSP:false.
    bypassCSP: true,
  },
  webServer: { command: "node ../site-tests/serve.js",
               url: "http://localhost:8123", reuseExistingServer: true },
};
