module.exports = {
  testDir: "./specs", retries: 0, reporter: "line",
  use: { baseURL: "http://localhost:8123" },
  webServer: { command: "node ../site-tests/serve.js",
               url: "http://localhost:8123", reuseExistingServer: true },
};
