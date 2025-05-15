const cors = require('cors');
const express = require('express');
const fetch = require('node-fetch').default;
require('dotenv').config();
const mammoth = require('mammoth');
const pdfParse = require('pdf-parse');
const Ajv = require('ajv');
const ajv = new Ajv();
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { createToken, createSecret, isTokenValid } = require('csrf');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const crypto = require('crypto');
const app = express();
const port = 3000;
const upload = multer({ dest: 'uploads/', limits: { fileSize: 30 * 1024 * 1024 } });

app.use(express.static('public'));
app.use(express.json());
app.use(cors());
app.use(cookieParser());

                                                // Настройка CSRF-защиты
                                                const csrfProtection = csrf({ 
                                                  cookie: true, // Хранение токена в куки
                                                  sameSite: 'strict', // Защита от CSRF-атак
                                                });
                                                app.use(csrfProtection);

// Настройки Точка банк
const TOCHKA_API_URL = 'https://enter.tochka.com/api/v2';
const TOCHKA_CLIENT_ID = process.env.TOCHKA_CLIENT_ID;
const TOCHKA_CLIENT_SECRET = process.env.TOCHKA_CLIENT_SECRET;
const TOCHKA_REDIRECT_URI = process.env.TOCHKA_REDIRECT_URI;

// Обработка файлов
async function processFile(filePath, ext) {
  try {
    if (['.docx', '.doc'].includes(ext)) {
      const result = await mammoth.extractRawText({ path: filePath });
      return result.value;
    }

    if (ext === '.pdf') {
      const dataBuffer = await fs.promises.readFile(filePath);
      const data = await pdfParse(dataBuffer);
      return data.text;
    }

    if (ext === '.txt') {
      return fs.promises.readFile(filePath, 'utf-8');
    }

    throw new Error('Неподдерживаемый формат файла');
  } catch (err) {
    throw new Error(`Ошибка обработки файла: ${err.message}`);
  }
}

app.get('/api/csrf-token', (req, res) => {
  const secret = createSecret(); // Generate a secret
  const token = createToken(secret); // Generate token from secret
  res.cookie('csrfSecret', secret, { httpOnly: true, secure: true }); // Store secret in cookie
  res.json({ csrfToken: token }); // Send token to client
});

app.post('/analyze', upload.single('file'), async (req, res) => {
  const { token } = req.body;
  const secret = req.cookies.csrfSecret;

  if (!isTokenValid(token, secret)) {
    return res.status(403).json({ error: 'CSRF-атака' });
  }
  
  let rawContent = '';
  try {
    console.log('Получен файл:', req.file);
    if (!req.file) throw new Error('Файл не загружен');
    const ext = path.extname(req.file.originalname).toLowerCase();
    
    const textContent = await processFile(req.file.path, ext);
    
    if (!textContent || textContent.trim().length < 100) {
      throw new Error('Документ не содержит читаемого текста');
    }
    console.log('Извлеченный текст:', textContent.substring(0, 500) + '...');

    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://your-site.com',
        'X-Title': 'Pravo/Prdec'
      },
      body: JSON.stringify({
        model: "deepseek/deepseek-r1:free",
        messages: [{
          role: "user",
          content: `Проанализируй судебное решение суда Российской Федерации и предоставь JSON-ответ строго в следующем формате:
          {
            "probability": число от 0 до 100 (вероятность успеха апелляции),
            "title": "Краткий заголовок результата",
            "subtitle": "Пояснение к результату",
            "keyPoints": ["Перечень ключевых моментов для апелляции (не менее трех пунктов) в соответствии с законами Российской Федерации"],
            "recommendations": "Рекомендации по дальнейшим действиям в соответствии с законами Российской Федерации"
          }
          Анализируй только следующий текст: \n${textContent.substring(0, 15000)}`
        }],
        response_format: {
          "type": "json_schema",
          "json_schema": {
            "name": "legal_analysis",
            "strict": true,
            "schema": {
              "type": "object",
              "properties": {
                "probability": {
                  "type": "number",
                  "description": "Вероятность успеха апелляции от 0 до 100"
                },
                "title": {
                  "type": "string",
                  "description": "Краткий заголовок результата"
                },
                "subtitle": {
                  "type": "string",
                  "description": "Пояснение к результату"
                },
                "keyPoints": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  },
                  "description": "Ключевые моменты для апелляции в соответствии с законами Российской Федерации"
                },
                "recommendations": {
                  "type": "string",
                  "description": "Рекомендации по дальнейшим действиям в соответствии с законами Российской Федерации"
                }
              },
              "required": ["probability", "title", "subtitle", "keyPoints", "recommendations"],
              "additionalProperties": false
            }
          }
        },
        temperature: 0
      })
    });

    console.log('Ответ от OpenRouter:', response.status); // Логирование статуса
    const data = await response.json();
    // Для моделей с reasoning сначала извлекаем JSON
    rawContent = data.choices[0]?.message?.content || '';
    console.log('Полный ответ от OpenRouter:', JSON.stringify(data, null, 2)); 
    if (!response.ok) {
      console.error('OpenRouter API Error:', data);
      throw new Error(data.error?.message || `HTTP Error: ${response.status}`);
    }
    if (!data.choices?.[0]?.message?.content) throw new Error('Пустой ответ от ИИ');
    const jsonStart = rawContent.indexOf('{');
    const jsonEnd = rawContent.lastIndexOf('}') + 1;  
    if (jsonStart === -1 || jsonEnd === 0) {
      throw new Error('JSON не найден в ответе');
    }
    const schema = {
      type: "object",
      properties: {
        probability: { type: "number", minimum: 0, maximum: 100 },
        title: { type: "string" },
        subtitle: { type: "string" },
        keyPoints: {
          type: "array",
          items: { type: "string" },
          minItems: 3
        },
        recommendations: { type: "string" }
      },
      required: ["probability", "title", "subtitle", "keyPoints", "recommendations"],
      additionalProperties: false
    };
    const jsonString = rawContent
      .slice(jsonStart, jsonEnd)
      .replace(/\\n/g, '')
      .replace(/\\/g, '');
  
    const result = JSON.parse(jsonString);
    const validate = ajv.compile(schema);
    if (!validate(result)) {
      throw new Error(`Некорректная схема: ${JSON.stringify(validate.errors)}`);
    }
    
  if (!result || !result.probability) {
  throw new Error('Некорректный формат ответа от ИИ');
}
    // Валидация по схеме
    if (!result.probability || result.probability < 0 || result.probability > 100) {
      throw new Error('Некорректное значение вероятности');
    }
     const sessionId = crypto.randomBytes(16).toString('hex');
    analysisSessions.set(sessionId, Result);
    
    // Формируем частичный результат для бесплатного отображения
    const limitedResult = {
      sessionId,
      probability: fullResult.probability,
      title: fullResult.title,
      subtitle: fullResult.subtitle.substring(0, 100) + '...',
      isPaid: false
    };
    
    res.json(limitedResult);
  } catch (err) {
    console.error('Ошибка:', {
      rawResponse: rawContent || 'N/A',
      error: err.message
    });
    res.status(500).json({ 
      error: err.message.includes('JSON') 
        ? 'Ошибка формата ответа ИИ' 
        : err.message 
    });
  }
});

async function getTochkaAccessToken() {
  try {
    const response = await axios.post(
      `${TOCHKA_API_URL}/oauth2/token`,
      {
        grant_type: 'client_credentials',
        client_id: TOCHKA_CLIENT_ID,
        client_secret: TOCHKA_CLIENT_SECRET,
        scope: 'payments'
      },
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    return response.data.access_token;
  } catch (error) {
    console.error('Ошибка получения токена:', error);
    throw error;
  }
}

// Маршрут создания платежа
app.post('/create-payment', async (req, res) => {
  try {
    const { sessionId } = req.body;
    const secret = req.cookies.csrfSecret;
    const token = req.body._csrf;

  if (!isTokenValid(token, secret)) {
    return res.status(403).json({ error: 'CSRF-атака' });
  }

  if (!sessionId || !analysisSessions.has(sessionId)) {
    return res.status(400).json({ error: 'Некорректная сессия' });
  }
    if (!sessionId || !analysisSessions.has(sessionId)) {
      return res.status(400).json({ error: 'Некорректная сессия анализа' });
    }
    const paymentId = crypto.randomBytes(8).toString('hex');
    const accessToken = await getTochkaAccessToken();
    
    // Создание платежа через API Точка банк
    const paymentData = {
      amount: 490, // Цена услуги
      currency: 'RUB',
      description: 'Полный анализ судебного решения',
      redirectUrl: `${req.protocol}://${req.get('host')}/payment-callback?sessionId=${sessionId}&paymentId=${paymentId}`,
      metadata: { sessionId, paymentId }
    };
    
    const tochkaResponse = await axios.post(
      `${TOCHKA_API_URL}/payment/order`,
      paymentData,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    res.json({ paymentUrl: tochkaResponse.data.redirectURL });
  } catch (error) {
    console.error('Ошибка создания платежа:', error);
    res.status(500).json({ error: 'Ошибка при создании платежа' });
  }
});

// Маршрут для получения полных результатов после оплаты
app.get('/full-analysis/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  
  // Проверяем оплату через куки
  if (!req.cookies.paidAnalysis || req.cookies.paidAnalysis !== sessionId) {
    return res.status(402).json({ error: 'Требуется оплата' });
  }
  
  if (!analysisSessions.has(sessionId)) {
    return res.status(404).json({ error: 'Анализ не найден' });
  }
  
  const fullResult = analysisSessions.get(sessionId);
  res.json({ ...fullResult, isPaid: true });
});

// Маршрут для обработки колбэка после оплаты
app.get('/payment-callback', async (req, res) => {
  const { sessionId, paymentId } = req.query;
  const secret = req.cookies.csrfSecret;
  const token = req.query._csrf;

  if (!isTokenValid(token, secret)) {
    return res.status(403).json({ error: 'CSRF-атака' });
  }
  if (!sessionId || !analysisSessions.has(sessionId)) {
    return res.status(400).json({ error: 'Некорректная сессия' });
  }
  
  try {
    const accessToken = await getTochkaAccessToken();
    const statusResponse = await axios.get(
      `${TOCHKA_API_URL}/payment/status/${paymentId}`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    );
    
    if (statusResponse.data.status === 'completed') {
      // Устанавливаем куку об оплате
      res.cookie('paidAnalysis', sessionId, { 
        maxAge: 86400000, // 24 часа
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
      });
      
      res.redirect(`/?payment=success&sessionId=${sessionId}`);
    } else {
      res.redirect('/?payment=failed');
    }
  } catch (error) {
    console.error('Ошибка проверки платежа:', error);
    res.redirect('/?payment=error');
  }
});

// Добавляем обработку корневого пути
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'PreDec.html'));
});

app.listen(port, () => console.log(`Сервер запущен на порту ${port}`));
