const app = require('./api/index');
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[DEV] AusDMusic Auth Server running on http://localhost:${PORT}`);
  console.log(`[DEV] Health Check: http://localhost:${PORT}/api/health`);
});
