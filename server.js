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
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "yourdomain.com"; // ← укажи свой домен

app.set("trust proxy", true);
app.use(helmet());
app.use(express.json());

// --- Разрешённые источники ---
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || origin.includes(ALLOWED_ORIGIN)) callback(null, true);
      else callback(new Error("Not allowed by CORS"));
    },
    methods: ["POST", "GET"],
  })
);

// --- Лимит запросов ---
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/lead", limiter);

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
  const okEmail = typeof body.email === "string" && /\S+@\S+\.\S+/.test(body.email);
  const okPhone = typeof body.phone === "string" && body.phone.trim().length >= 7;
  const okName = typeof body.name === "string" && body.name.trim().length >= 2;
  const okSku = typeof body.sku === "string" && body.sku.trim().length > 0;
  return okEmail && okPhone && okName && okSku;
}

// --- Главный маршрут ---
app.post("/api/lead", async (req, res) => {
  try {
    const body = req.body;
    const ip = req.ip;

    // 1️⃣ Проверка источника запроса
    const origin = req.get("origin") || req.get("referer") || "";
    if (!origin.includes(ALLOWED_ORIGIN)) {
      return res.status(403).json({ ok: false, message: "Invalid origin" });
    }

    // 2️⃣ Honeypot (динамическое имя)
    const honeypotTriggered = Object.entries(body).some(
      ([key, value]) => key.startsWith("hp_") && value && value.trim() !== ""
    );
    if (honeypotTriggered) {
      return res.status(400).json({ ok: false, message: "Bot detected (honeypot)" });
    }

    // 3️⃣ Проверка времени заполнения
    if (!body.form_time || Number(body.form_time) < 3) {
      return res.status(400).json({ ok: false, message: "Too fast submission" });
    }

    // 4️⃣ JS-токен
    if (!body.js_token || typeof body.js_token !== "string" || body.js_token.length < 20) {
      return res.status(400).json({ ok: false, message: "Missing JS token" });
    }

    // 5️⃣ Проверка основных полей
    if (!validatePayload(body)) {
      return res.status(400).json({ ok: false, message: "Invalid input" });
    }

    // 6️⃣ Проверка Turnstile
    if (!body.turnstileToken) {
      return res.status(400).json({ ok: false, message: "Captcha token required" });
    }

    const verify = await verifyTurnstile(body.turnstileToken, ip);
    console.log("Turnstile verify response:", verify);

    if (!verify?.success) {
      return res.status(403).json({ ok: false, message: "Captcha verification failed" });
    }

    // (опционально) Проверяем score, если есть
    if (verify?.score !== undefined && verify.score < 0.5) {
      return res.status(403).json({ ok: false, message: "Low captcha score" });
    }

    // 7️⃣ Создание лида
    const leadId = crypto.randomBytes(8).toString("hex");

    // --- Отправка в Bitrix24 ---
    if (BITRIX_WEBHOOK) {
      try {
        const bitrixRes = await fetch(BITRIX_WEBHOOK, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            fields: {
              TITLE: `Wholesale Lead US`,
              NAME: body.name,
              PHONE: [{ VALUE: body.phone, VALUE_TYPE: "WORK" }],
              EMAIL: [{ VALUE: body.email, VALUE_TYPE: "WORK" }],
              COMPANY_TITLE: body.company || "",
              COMMENTS: `SKU/INFO: ${body.sku}\nFrom ${body.page_location || ""}\nBy ${body.name}`,
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
    console.error("Lead error", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
