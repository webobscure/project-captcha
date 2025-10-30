import express from "express";
import fetch from "node-fetch";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import crypto from "crypto";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET;
const BITRIX_WEBHOOK = process.env.BITRIX_WEBHOOK;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "onkron.us";

// --- Настройка Express ---
app.set("trust proxy", true);
app.use(helmet());
app.use(express.json());

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || origin.includes(ALLOWED_ORIGIN)) callback(null, true);
      else callback(new Error("Not allowed by CORS"));
    },
    methods: ["POST", "GET"],
  })
);

// --- Rate limit по IP ---
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 минута
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/lead", limiter);

// --- Простейший кеш для частых лидов ---
const recentIps = new Map();

// --- Проверка Turnstile ---
async function verifyTurnstile(token, remoteip) {
  const url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
  const params = new URLSearchParams();
  params.append("secret", TURNSTILE_SECRET);
  params.append("response", token);
  if (remoteip) params.append("remoteip", remoteip);

  const res = await fetch(url, { method: "POST", body: params });
  return res.json();
}

// --- Валидация формы ---
function validatePayload(body) {
  const okEmail =
    typeof body.email === "string" && /\S+@\S+\.\S+/.test(body.email);
  const okPhone =
    typeof body.phone === "string" && body.phone.trim().length >= 7;
  const okName = typeof body.name === "string" && body.name.trim().length >= 2;
  const okSku = typeof body.sku === "string" && body.sku.trim().length > 0;
  return okEmail && okPhone && okName && okSku;
}

// --- Главный маршрут ---
app.post("/api/lead", async (req, res) => {
  try {
    const body = req.body;
    const ip = req.ip;
    const now = Date.now();

    // --- 1️⃣ Проверка origin (CORS) ---
    const origin = (req.get("origin") || "").replace(/\/$/, "");
    if (origin && !origin.includes(ALLOWED_ORIGIN)) {
      console.warn("Blocked by origin check:", { ip, origin });
      return res.status(403).json({ ok: false, message: "Invalid origin" });
    }

    // --- 2️⃣ Проверка page_location / referrer для инфо ---
    const page = body.page_location || "";
    const ref = body.page_referrer || "";
    const suspiciousDomains = [/google/i, /gclid=/i];
    if (suspiciousDomains.some((r) => r.test(page) || r.test(ref))) {
      console.warn("Suspicious domain detected:", { ip, page, ref });
      return res.status(400).json({ ok: false, message: "Suspicious referrer" });
    }

    // --- 3️⃣ Honeypot ---
    const honeypotTriggered = Object.entries(body).some(
      ([key, value]) => key.startsWith("hp_") && value && value.trim() !== ""
    );
    if (honeypotTriggered) {
      console.warn("Honeypot triggered:", { ip, body });
      return res.status(400).json({ ok: false, message: "Bot detected (honeypot)" });
    }

    // --- 4️⃣ Проверка времени заполнения ---
    if (!body.form_time || Number(body.form_time) < 3) {
      console.warn("Form submitted too fast:", { ip, form_time: body.form_time });
      return res.status(400).json({ ok: false, message: "Too fast submission" });
    }

    // --- 5️⃣ JS-токен ---
    if (!body.js_token || typeof body.js_token !== "string" || body.js_token.length < 20) {
      console.warn("Missing or invalid JS token:", { ip });
      return res.status(400).json({ ok: false, message: "Missing JS token" });
    }

    // --- 6️⃣ Проверка полей ---
    if (!validatePayload(body)) {
      console.warn("Invalid payload:", { ip, body });
      return res.status(400).json({ ok: false, message: "Invalid input" });
    }

    // --- 7️⃣ Проверка имени + телефона ---
    const name = (body.name || "").trim();
    const phone = (body.phone || "").replace(/\D/g, "");
    const isLatin = /^[A-Za-z\s]+$/.test(name);
    const isCyrillic = /[А-Яа-яЁё]/.test(name);
    if ((isLatin && phone.startsWith("7")) || (isCyrillic && phone.startsWith("1"))) {
      console.warn("Suspicious name+phone combo:", { ip, name, phone });
      return res.status(400).json({ ok: false, message: "Suspicious combination" });
    }

    // --- 8️⃣ Rate-limit вручную (3 лида / минута) ---
    const history = recentIps.get(ip) || [];
    const newHistory = [...history.filter((t) => now - t < 60_000), now];
    recentIps.set(ip, newHistory);
    if (newHistory.length > 3) {
      console.warn("Too many leads from one IP:", ip);
      return res.status(429).json({ ok: false, message: "Too many requests" });
    }

    // --- 8.5 Определяем источник формы через маппинг ---
    const sourceMap = {
      openWholesaleHeader: "с Шапки",
      openWholesaleFooter: "с Футера",
      page: "со страницы",
      modal: "из модалки"
    };

    let source = "unknown";
    if (body.button_id && typeof body.button_id === "string") {
      source = sourceMap[body.button_id] || body.button_id;
    } else if (body.source && typeof body.source === "string") {
      source = sourceMap[body.source] || body.source;
    }
    body.source = source;

    // --- 9️⃣ Проверка Turnstile ---
    if (!body.turnstileToken) {
      return res.status(400).json({ ok: false, message: "Captcha token required" });
    }
    const verify = await verifyTurnstile(body.turnstileToken, ip);
    console.log("Turnstile verify response:", verify);
    if (!verify?.success || (verify?.score !== undefined && verify.score < 0.5)) {
      return res.status(403).json({ ok: false, message: "Captcha verification failed" });
    }

    // --- 10️⃣ Создание лида ---
    const leadId = crypto.randomBytes(8).toString("hex");

    // --- 11️⃣ Отправка в Bitrix24 ---
    if (BITRIX_WEBHOOK) {
      try {
        const bitrixRes = await fetch(BITRIX_WEBHOOK, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            fields: {
              TITLE: `Wholesale Lead`,
              NAME: body.name,
              PHONE: [{ VALUE: body.phone, VALUE_TYPE: "WORK" }],
              EMAIL: [{ VALUE: body.email, VALUE_TYPE: "WORK" }],
              COMPANY_TITLE: body.company || "",
              COMMENTS: `SKU/INFO: ${body.sku}\nFrom ${body.page_location || ""}\nForm source: ${body.source}\nBy ${body.name}`,
              SOURCE_ID: "WEBFORM",
              UTM_SOURCE: body.page_location || "",
              WEBFORM_URL: body.page_location || "",
            },
            params: { REGISTER_SONET_EVENT: "Y" },
          }),
        });
        const bitrixData = await bitrixRes.json();
        console.log("Bitrix24 response:", bitrixData);
      } catch (err) {
        console.error("Bitrix24 error:", err);
      }
    }

    // ✅ Успешный ответ
    return res.json({ ok: true, lead_id: leadId, message: "Lead saved" });
  } catch (err) {
    console.error("Lead error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
