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
// const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET;
const BITRIX_WEBHOOK = process.env.BITRIX_WEBHOOK;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "onkron.us";

// --- Настройка Express ---
app.set("trust proxy", true);

app.use(helmet());
// --- Лог IP ---
app.use((req, res, next) => {
  console.log(
    "Incoming request from IP:",
    req.ip,
    "via X-Forwarded-For:",
    req.headers["x-forwarded-for"]
  );
  next();
});

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
// async function verifyTurnstile(token, remoteip) {
//   const url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
//   const params = new URLSearchParams();
//   params.append("secret", TURNSTILE_SECRET);
//   params.append("response", token);
//   if (remoteip) params.append("remoteip", remoteip);

//   const res = await fetch(url, { method: "POST", body: params });
//   return res.json();
// }

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

    console.log("Lead received:", body);

    // --- Проверка origin (CORS) ---
    const origin = (req.get("origin") || "").replace(/\/$/, "");
    const allowedOrigins = ["onkron.us", "www.onkron.us", "onkron.com"];
    if (origin && !allowedOrigins.some((o) => origin.includes(o))) {
      console.warn("Blocked by origin:", { ip, origin });
      return res.status(403).json({ ok: false, message: "Invalid origin" });
    }

    // --- Honeypot ---
    const honeypotTriggered = Object.entries(body).some(
      ([key, value]) => key.startsWith("hp_") && value && value.trim() !== ""
    );
    if (honeypotTriggered) {
      console.warn("Honeypot triggered:", { ip, body });
      return res
        .status(400)
        .json({ ok: false, message: "Bot detected (honeypot)" });
    }

    // --- Проверка времени заполнения ---
    const formTime = Number(body.form_time || 0);
    if (formTime < 1) {
      console.warn("Form submitted too fast:", { ip, form_time: formTime });
      // не блокируем, просто логируем
    }

    // --- Проверка обязательных полей ---
    if (!validatePayload(body)) {
      console.warn("Invalid payload:", { ip, body });
      return res.status(400).json({ ok: false, message: "Invalid input" });
    }

    // --- Проверка имени и телефона (мягко) ---
    const name = (body.name || "").trim();
    const phone = (body.phone || "").replace(/\D/g, "");
    const isLatin = /^[A-Za-z\s]+$/.test(name);
    const isCyrillic = /[А-Яа-яЁё]/.test(name);
    if (
      (isLatin && phone.startsWith("7")) ||
      (isCyrillic && phone.startsWith("1"))
    ) {
      console.warn("Suspicious name+phone combo:", { ip, name, phone });
      return res
        .status(450)
        .json({ ok: false, message: "Suspicious name+phone combo" });
    }

    // --- Rate-limit вручную (до 10 лидов / минута с IP) ---
    const history = recentIps.get(ip) || [];
    const newHistory = [...history.filter((t) => now - t < 60_000), now];
    recentIps.set(ip, newHistory);
    if (newHistory.length > 3) {
      console.warn("Too many leads from one IP:", ip);
      return res.status(429).json({ ok: false, message: "Too many requests" });
    }

    // --- Определяем источник формы ---
    const sourceMap = {
      openWholesaleHeader: "с Шапки",
      openWholesaleFooter: "с Футера",
      solutions: "со страницы business solutions",
      distributor: "со страницы distributor",
      page: "со страницы",
      modal: "из модалки на странице продукта",
    };
    let source = "unknown";
    if (body.button_id && typeof body.button_id === "string") {
      source = sourceMap[body.button_id] || body.button_id;
    } else if (body.source && typeof body.source === "string") {
      source = sourceMap[body.source] || body.source;
    }
    body.source = source;

    // --- Создание лида ---
    const leadId = crypto.randomBytes(8).toString("hex");

    // --- Отправка в Bitrix ---
    if (BITRIX_WEBHOOK) {
      try {
        const bitrixRes = await fetch(BITRIX_WEBHOOK, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            fields: {
              TITLE: `Заполнение CRM-формы "Onkron US"`,
              NAME: body.name,
              PHONE: [{ VALUE: body.phone, VALUE_TYPE: "WORK" }],
              EMAIL: [{ VALUE: body.email, VALUE_TYPE: "WORK" }],
              COMPANY_TITLE: body.company || "",
              COMMENTS: `SKU/INFO: ${body.sku}\nFrom ${
                body.page_location || ""
              }\nForm source: ${body.source}\nBy ${body.name}`,
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

    return res.json({ ok: true, lead_id: leadId, message: "Lead saved" });
  } catch (err) {
    console.error("Lead error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});
// --- Маршрут для HeyForm ---
app.post("/api/heyform", async (req, res) => {
  try {
    const ip = req.ip;
    const body = req.body;

    console.log("HeyForm Lead received:", body);

    // --- CORS Проверка ---
    const origin = (req.get("origin") || "").replace(/\/$/, "");
    const allowedOrigins = ["onkron.us", "www.onkron.us", "onkron.com"];
    if (origin && !allowedOrigins.some((o) => origin.includes(o))) {
      console.warn("Blocked by origin:", { ip, origin });
      return res.status(403).json({ ok: false, message: "Invalid origin" });
    }

    // --- Проверка структуры HeyForm ---
    if (!body.answers || !Array.isArray(body.answers)) {
      console.warn("Invalid HeyForm structure:", body);
      return res.status(400).json({ ok: false, message: "Invalid structure" });
    }

    // --- Достаём поля из answer ---
    const mapValue = (title) => {
      const item = body.answers.find((a) =>
        a.title?.toLowerCase().includes(title.toLowerCase())
      );
      return item?.value || "";
    };

    const name = mapValue("name") || mapValue("contact name");
    const email = mapValue("email");
    const phone = mapValue("phone");
    const company = mapValue("company");
    const sku = mapValue("SKU/Info") || "";

    // --- Проверка обязательных полей ---
    if (!email || !/\S+@\S+\.\S+/.test(email)) {
      return res.status(400).json({ ok: false, message: "Invalid email" });
    }

    if (!phone || String(phone).replace(/\D/g, "").length < 7) {
      return res.status(400).json({ ok: false, message: "Invalid phone" });
    }

    if (!name || name.length < 2) {
      return res.status(400).json({ ok: false, message: "Invalid name" });
    }

    // --- Rate-limit вручную ---
    const now = Date.now();
    const history = recentIps.get(ip) || [];
    const newHistory = [...history.filter((t) => now - t < 60_000), now];
    recentIps.set(ip, newHistory);

    if (newHistory.length > 4) {
      console.warn("Too many HeyForm leads:", ip);
      return res.status(429).json({ ok: false, message: "Too many requests" });
    }

    // --- Lead ID ---
    const leadId = crypto.randomBytes(8).toString("hex");

    // --- Отправка в Bitrix ---
    if (BITRIX_WEBHOOK) {
      try {
        const bitrixRes = await fetch(BITRIX_WEBHOOK, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            fields: {
              TITLE: `Lead from HeyForm (${body.formName || ""})`,
              NAME: name,
              PHONE: [{ VALUE: phone, VALUE_TYPE: "WORK" }],
              EMAIL: [{ VALUE: email, VALUE_TYPE: "WORK" }],
              COMPANY_TITLE: company || "",
              COMMENTS: `SKU/INFO: ${sku}\nForm ID: ${body.formId}\nSubmission ID: ${body.id}`,
              SOURCE_ID: "WEBFORM",
              WEBFORM_URL: body.formName || "",
            },
            params: { REGISTER_SONET_EVENT: "Y" },
          }),
        });

        const bitrixData = await bitrixRes.json();
        console.log("Bitrix24 (HeyForm) response:", bitrixData);
      } catch (err) {
        console.error("Bitrix24 (HeyForm) error:", err);
      }
    }

    return res.json({
      ok: true,
      lead_id: leadId,
      message: "HeyForm lead saved",
    });
  } catch (err) {
    console.error("HeyForm lead error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
