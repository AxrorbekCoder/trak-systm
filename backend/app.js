const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const PizZip = require('pizzip');
const Docxtemplater = require('docxtemplater');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const Invoice = require('./models/Invoice');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Настройки подключения к базе данных
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Подключение к базе данных
db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL');
});

// JWT Secret
const jwtSecret = process.env.JWT_SECRET;

// Rate limiter for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5 // Limit each IP to 5 requests per windowMs
});

// Middleware для проверки JWT и ролей пользователей
const authMiddleware = (roles) => (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(403).send('No token provided');
  
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) return res.status(403).send('Invalid token');
    if (!roles.includes(decoded.role)) return res.status(403).send('Access denied');
    req.user = decoded;
    next();
  });
};

// Регистрация клиентов
app.post('/register', [
  body('username').isString().isLength({ min: 3 }),
  body('password').isString().isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.query('INSERT INTO users (username, password, role) VALUES (?, ?, "client")',
    [username, hashedPassword],
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.status(201).send('User registered');
    });
});

// Логин
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, result) => {
    if (err || result.length === 0) return res.status(401).send('User not found');
    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send('Invalid credentials');

    const token = jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Примеры защищённых маршрутов
app.get('/admin/dashboard', authMiddleware(['admin']), (req, res) => {
  res.send('Welcome to the admin dashboard');
});

// Получение данных клиентов
app.get('/api/clients', (req, res) => {
  db.query('SELECT * FROM clients', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

// Функция для генерации номера инвойса
const generateInvoiceNumber = async () => {
  return new Promise((resolve, reject) => {
    db.query('SELECT COUNT(*) as count FROM invoices', (err, result) => {
      if (err) return reject(err);
      const count = result[0].count + 1;
      const invoiceNumber = `IN${String(count).padStart(2, '0')}`;
      resolve(invoiceNumber);
    });
  });
};

app.get('/api/invoices/:trackingCode', async (req, res) => {
  const trackingCode = req.params.trackingCode;

  try {
    const invoice = await Invoice.findOne({ where: { tracking_code: trackingCode } });

    if (!invoice) {
      return res.status(404).json({ message: 'Трек-код не найден' });
    }

    res.json({ status: invoice.status });
  } catch (error) {
    console.error('Ошибка при получении данных:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
});



app.get('/api/invoices/:trackingCode', async (req, res) => {
  const trackingCode = req.params.trackingCode;

  try {
    const invoice = await Invoice.findOne({ where: { tracking_code: trackingCode } });

    if (!invoice) {
      return res.status(404).json({ message: 'Трек-код не найден' });
    }

    const gifMap = {
      'In Airplane': 'path_to_airplane_gif.gif',
      'In Warehouse': 'path_to_warehouse_gif.gif',
      'In Collection': 'path_to_collection_gif.gif',
      'Unknown': 'path_to_unknown_gif.gif',
    };

    res.json({
      status: invoice.status,
      gif: gifMap[invoice.status] || gifMap['Unknown'],
    });
  } catch (error) {
    console.error('Ошибка при получении данных:', error); // Логирование ошибки
    res.status(500).json({ message: 'Внутренняя ошибка сервера', error: error.message });
  }
});










app.post('/api/invoices/generate-docx', [
  body('clientId').isNumeric(),
  body('invoiceDetails').isObject(),
  body('invoiceDetails.invoice_date').notEmpty().withMessage('Invoice date is required'),
  body('invoiceDetails.products').isArray().withMessage('Products should be an array'),
  body('invoiceDetails.client_account').notEmpty().withMessage('Client account is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { clientId, invoiceDetails } = req.body;
  const { client_phone, client_address, invoice_date, shop_name, product_link, product_name, color, quantity, size, product_code, sum, products, tracking_code, client_account } = invoiceDetails;

  try {
    const invoiceNumber = await generateInvoiceNumber();

    // Загрузка шаблона DOCX
    const content = fs.readFileSync(path.resolve(__dirname, 'template.docx'), 'binary');
    const zip = new PizZip(content);
    const doc = new Docxtemplater(zip);

    // Подготовка данных для заполнения шаблона
    const data = {
      client_phone,
      client_address,
      invoice_date,
      shop_name,
      product_link,
      product_name,
      color,
      quantity,
      size,
      product_code,
      sum,
      products: products.map(product => ({
        name: product.product_name || 'Unknown',  // Проверка и замена пустых полей
        color: product.color || 'N/A',
        quantity: product.quantity || '1',
        size: product.size || 'N/A',
        code: product.product_code || 'Unknown',
        amount: product.amount || '0'
      })),
      tracking_code,
      client_account,
      invoiceNumber
    };

    // Логирование данных для проверки
    console.log("Invoice Data:", data);

    // Установка данных в шаблон
    doc.setData(data);

    try {
      // Рендеринг документа
      doc.render();
    } catch (error) {
      console.error('Ошибка при рендеринге документа:', error);
      return res.status(500).json({ error: 'Ошибка при генерации документа' });
    }

    // Генерация файла
    const buffer = doc.getZip().generate({ type: 'nodebuffer' });
    const docxPath = path.resolve(__dirname, `invoices/${invoiceNumber}.docx`);

    // Сохранение файла DOCX
    fs.writeFileSync(docxPath, buffer);

    // Преобразование массива продуктов в строку JSON для сохранения в базе данных
    const productsString = JSON.stringify(products.map(product => ({
      name: product.product_name || 'Unknown',
      color: product.color || 'N/A',
      quantity: product.quantity || '1',
      size: product.size || 'N/A',
      code: product.product_code || 'Unknown',
      amount: product.amount || '0'
    })));

    // Сохранение информации в базу данных
    db.query('INSERT INTO invoices (client_id, invoice_number, tracking_code, docx_url, invoice_date, client_phone, shop_name, product_link, products, client_account, product_name, color, quantity, size, product_code, sum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [clientId, invoiceNumber, tracking_code || null, `http://localhost:3001/invoices/${invoiceNumber}.docx`, invoice_date, client_phone, shop_name, product_link, productsString, client_account || null, product_name, color, quantity, size, product_code, sum],
      (err, result) => {
        if (err) {
          console.error('Ошибка базы данных:', err);
          return res.status(500).json({ error: 'Ошибка базы данных' });
        }
        res.json({ docxUrl: `http://localhost:3001/invoices/${invoiceNumber}.docx` });
      }
    );

  } catch (error) {
    console.error('Ошибка при генерации инвойса:', error);
    res.status(500).json({ error: 'Ошибка при генерации инвойса' });
  }
});


// Статическая папка для файлов инвойсов
app.use('/invoices', express.static(path.join(__dirname, 'invoices')));

// Запуск сервера
const PORT = 3001;

// Check if port is in use and handle the error
const server = app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Please choose another port.`);
  } else {
    console.error('Error occurred:', err);
  }
});
