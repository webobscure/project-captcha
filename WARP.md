# README.md

Этот файл содержит руководство  при работе с кодом в этом репозитории.

## Обзор проекта

BTB Form — это Node.js/Express backend-сервис для приёма заявок с формы с верификацией CAPTCHA через Cloudflare Turnstile. Приложение представляет собой защищённый от ботов API endpoint для сбора информации о лидах (email, телефон, имя, артикул).


### Запуск сервера
```bash
npm start
```
Запускает Express-сервер на порту 3000 (или PORT из переменных окружения).

### Установка зависимостей
```bash
npm install
```

## Архитектура

### Однофайловый Backend
Вся логика backend находится в `server.js` как ES-модуль (`"type": "module"` в package.json). Это лёгкий API-сервер с единственной целью.

### Поток обработки запроса
1. **Rate limiting** (express-rate-limit): 20 запросов за 60 секунд с одного IP на `/api/lead`
2. **Security middleware** (helmet): HTTP заголовки безопасности
3. **CORS**: Разрешает все источники (`*`) для методов POST/GET
4. **Обнаружение ботов**: Проверка honeypot-поля (`hp_field`)
5. **Валидация**: Email regex, длина телефона ≥7, длина имени ≥2, наличие SKU
6. **Верификация CAPTCHA**: Cloudflare Turnstile через функцию `verifyTurnstile()`
7. **Ответ**: Возвращает JSON с `lead_id` (сгенерированная crypto hex-строка)

### Ключевые зависимости
- **express**: Web-фреймворк
- **node-fetch**: HTTP-клиент для вызовов Turnstile API
- **express-rate-limit**: Rate limiting по IP
- **helmet**: Заголовки безопасности
- **cors**: Cross-origin resource sharing
- **dotenv**: Управление переменными окружения

### Конфигурация окружения
Требуются в `.env`:
- `TURNSTILE_SECRET`: Секретный ключ Cloudflare Turnstile (сейчас хранится в `.env` - убедитесь, что не коммитите в продакшен)
- `PORT`: Опционально, по умолчанию 3000

### API Endpoint

**POST /api/lead**

Тело запроса:
```json
{
  "email": "user@example.com",
  "phone": "1234567890",
  "name": "Иван Иванов",
  "sku": "PRODUCT-123",
  "turnstileToken": "captcha_token_from_frontend",
  "hp_field": "" // honeypot, должно быть пустым/отсутствовать
}
```

Ответ (успех):
```json
{
  "ok": true,
  "lead_id": "a1b2c3d4e5f6g7h8",
  "message": "Lead saved"
}
```

### Меры безопасности
- Rate limiting на уровне endpoint (20 запросов/мин)
- Заголовки безопасности Helmet.js
- Honeypot-поле (`hp_field`) для обнаружения ботов
- Серверная верификация CAPTCHA (Cloudflare Turnstile)
- Валидация всех обязательных полей



## Соглашения по коду
- Синтаксис ES-модулей (`import`/`export`)
- Async/await для асинхронных операций
- Русские комментарии в оригинальном коде (кириллица)
- Ответы с ошибками включают `ok: false` + описательное поле `message`
- Console.log для отладки верификации Turnstile
