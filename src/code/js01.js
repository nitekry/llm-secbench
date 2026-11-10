const express = require("express");
const { requireLogin } = require("./auth");
const db = require("./db");

const router = express.Router();

router.get("/invoices", requireLogin, async (req, res) => {
  const rows = await db.query(
    "SELECT id, total, status, created_at FROM invoices WHERE owner_id = $1 ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json(rows);
});

router.get("/invoices/:id", requireLogin, async (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "bad id" });

  const rows = await db.query(
    "SELECT id, owner_id, total, status, items, billing_address FROM invoices WHERE id = $1", // @@VULN@@
    [id]
  );
  if (rows.length === 0) return res.status(404).json({ error: "not found" });
  res.json(rows[0]);
});

router.post("/invoices/:id/pay", requireLogin, async (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "bad id" });

  const result = await db.query(
    "UPDATE invoices SET status = 'paid' WHERE id = $1 AND owner_id = $2 AND status = 'open' RETURNING id",
    [id, req.user.id]
  );
  if (result.length === 0) return res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

module.exports = router;
