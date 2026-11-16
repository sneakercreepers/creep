// Inventory service: Express in TypeScript with routers, mounts and
// middleware-based auth. Test fixture for creep's static extraction only.

import express, { Request, Response, NextFunction, Router } from "express";
import { execFile } from "node:child_process";
import * as fs from "fs/promises";
import axios from "axios";
import passport from "passport";
import { Pool } from "pg";

const pool = new Pool();
const app = express();
app.use(express.json());

function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (req.get("x-role") !== "admin") {
    res.sendStatus(403);
    return;
  }
  next();
}

const asyncHandler = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response) => fn(req, res);

async function loadItem(id: string) {
  return pool.query("SELECT * FROM items WHERE id = $1", [id]);
}

// Declared before any auth middleware: public.
app.get("/health", (req: Request, res: Response) => {
  res.json({ ok: true });
});

app.get("/export/:name", async (req: Request, res: Response) => {
  const data = await fs.readFile(`/srv/exports/${req.params.name}`);
  res.send(data);
});

const items = Router();
items.get("/", async (req: Request, res: Response) => {
  const sort: string = req.query.sort as string;
  const rows = await pool.query("SELECT * FROM items ORDER BY " + sort);
  res.json(rows.rows);
});
items.get("/:id", asyncHandler(async (req: Request, res: Response) => {
  res.json(await loadItem(req.params.id));
}));
items
  .route("/:id/preview")
  .get((req: Request, res: Response) => {
    res.render("preview", { id: req.params.id });
  })
  .post(requireAdmin, async (req: Request, res: Response) => {
    const out = await axios.get(req.body.url);
    res.json(out.data);
  });

const admin = express.Router();
admin.use(passport.authenticate("jwt", { session: false }));
admin.delete("/cache", (req: Request, res: Response) => {
  const dir = "/var/cache/inventory";
  execFile("rm", ["-rf", dir], () => res.sendStatus(204));
});

app.use("/api/items", items);
app.use("/api/admin", admin);

app.use("/reports", requireAdmin);
app.get("/reports/daily", (req: Request, res: Response) => {
  res.sendFile("/srv/reports/daily.csv");
});
app.get("/reportsx", (req: Request, res: Response) => {
  res.sendFile(req.path);
});

export default app;
