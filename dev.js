# AusDMusic Auth API - Local Development Entrypoint
const app = require('./api/server');
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log([DEV] AusDMusic Auth Server running on http://localhost:);
  console.log([DEV] Health Check: http://localhost:/api/health);
});
