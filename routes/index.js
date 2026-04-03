import express from "express";
import cors from "cors";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

app.use(cors());
app.use("/api/webhook", express.raw({ type: "application/json" }));
app.use(express.json());

app.post("/api/webhook", async (req, res) => {
  const secret = process.env.LEMON_SQUEEZY_WEBHOOK_SECRET;
  const signature = req.headers["x-signature"];
  const body = req.body;

  const hmac = crypto.createHmac("sha256", secret);
  const digest = hmac.update(body).digest("hex");

  if (signature !== digest) {
    return res.status(401).send("Invalid signature");
  }

  const event = JSON.parse(body);
  console.log("Event:", event.meta?.event_name);

  if (event.meta?.event_name === "license_key_created") {
    const key = event.data.attributes.key;
    const email = event.data.attributes.user_email;
    const { error } = await supabase
      .from("licenses")
      .insert({ key, email, active: true });
    if (error) console.error("Supabase error:", error);
    else console.log("License saved:", key);
  }

  if (event.meta?.event_name === "order_refunded") {
    const email = event.data.attributes.user_email;
    await supabase
      .from("licenses")
      .update({ active: false })
      .eq("email", email);
    console.log("License deactivated for:", email);
  }

  res.sendStatus(200);
});

app.post("/api/verify", async (req, res) => {
  const { key, hwid } = req.body;

  if (!key || !hwid) return res.json({ valid: false });

  const { data: license, error } = await supabase
    .from("licenses")
    .select("*")
    .eq("key", key)
    .single();

  if (error || !license || !license.active) {
    return res.json({ valid: false });
  }

  if (!license.hwid) {
    await supabase
      .from("licenses")
      .update({ hwid })
      .eq("key", key);
    return res.json({ valid: true });
  }

  if (license.hwid !== hwid) {
    return res.json({ valid: false, reason: "License bound to another device" });
  }

  res.json({ valid: true });
});

app.get("/", (req, res) => res.send("AV8 backend running ✅"));

app.listen(process.env.PORT || 3000, () => console.log("Server running"));
