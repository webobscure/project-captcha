import express from "express";
import fetch from "node-fetch"; // или встроенный fetch в Node 18+
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import crypto from "crypto";
import dotenv from "dotenv";
import cors from "cors";
dotenv.config();

const app = express();

app.set('trust proxy', true); 

app.use(helmet());
app.use(express.json());
app.use(
  cors({
    origin: "*", 
    methods: ["POST", "GET"],
  })
);
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET; 
const PORT = process.env.PORT || 3000;

const limiter = rateLimit({
  windowMs: 60 * 1000, 
  max: 20, 
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/lead", limiter);

function validatePayload(body) {
  const okEmail =
    typeof body.email === "string" && /\S+@\S+\.\S+/.test(body.email);
  const okPhone =
    typeof body.phone === "string" && body.phone.trim().length >= 7;
  const okName = typeof body.name === "string" && body.name.trim().length >= 2;
  const okSku = typeof body.sku === "string" && body.sku.trim().length > 0;
  return okEmail && okPhone && okName && okSku;
}

async function verifyTurnstile(token, remoteip) {
  const url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
  const params = new URLSearchParams();
  params.append("secret", TURNSTILE_SECRET);
  params.append("response", token);
  if (remoteip) params.append("remoteip", remoteip);

  const res = await fetch(url, { method: "POST", body: params });
  return res.json();
}

app.post('/api/lead', async (req, res) => {
    try {
      const body = req.body;
      const ip = req.ip;
  
      // 1️⃣ honeypot
      if (body.hp_field) {
        return res.status(400).json({ ok: false, message: 'Bot detected' });
      }
  
      // 2️⃣ базовая валидация
      if (!validatePayload(body)) {
        return res.status(400).json({ ok: false, message: 'Invalid input' });
      }
  
      // 3️⃣ обязательная капча
      if (!body.turnstileToken) {
        return res.status(400).json({ ok: false, message: 'Captcha token required' });
      }
  
      // 4️⃣ проверяем капчу у Cloudflare
      
      const verify = await verifyTurnstile(body.turnstileToken, ip);
      console.log('Turnstile verify response:', verify);
      if (!verify?.success) {
        console.warn('Turnstile fail:', verify);
        return res.status(403).json({ ok: false, message: 'Captcha verification failed' });
      }
  
      // 5️⃣ генерируем ID лида (можно заменить на запись в БД)
      const leadId = crypto.randomBytes(8).toString('hex');
  
      // TODO: здесь можно сохранить лид в базу, CRM и т.д.
  
      // 6️⃣ возвращаем ответ — фронт сам отправит dataLayer.push
      return res.json({
        ok: true,
        lead_id: leadId,
        message: 'Lead saved',
      });
    } catch (err) {
      console.error('Lead error', err);
      res.status(500).json({ ok: false, message: 'Server error' });
    }
  });



app.listen(PORT, () => console.log(`Server ${PORT}`));
