// config.example.js - copy this file to config.js and fill in the API key.
// config.js is in .gitignore so the real key never reaches GitHub.
//
// WARNING: everything in config.js is visible to anyone who opens the dashboard
// (View Source / DevTools). The API key is DEMO-LEVEL protection only.

window.APPFLOW_CONFIG = {
  // Default: the same computer that served this page, port 8000 (works on laptop and phone).
  BACKEND_URL: location.protocol.startsWith("http")
    ? `${location.protocol}//${location.hostname}:8000`
    : "http://localhost:8000",

  // Copy API_KEY from the backend's .env file.
  API_KEY: "PASTE_API_KEY_FROM_.env_HERE",

  // Minimum time between two dashboard refreshes while live data streams in (milliseconds).
  REFRESH_MS: 2000,
};
