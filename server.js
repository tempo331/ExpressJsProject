const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const config = require('./config');

const pool = new Pool(config);
const app = express();

app.use(bodyParser.json());
app.use(cors());

const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).send('Access Denied');

    jwt.verify(token, config.secret, (err, user) => {
        if (err) return res.status(403).send('Invalid Token');
        req.user = user;
        next();
    });
};

app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const result = await pool.query(
            'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING *',
            [username, hashedPassword, role]
        );

        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, role: user.role }, config.secret);
        res.status(201).json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [
            username,
        ]);

        const user = result.rows[0];

        if (!user) return res.status(401).send('Invalid username or password');

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword)
            return res.status(401).send('Invalid username or password');

        const token = jwt.sign({ id: user.id, role: user.role }, config.secret);
        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.post('/add-product', authenticateToken, upload.array('images', 5), async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).send('У вас нет прав для выполнения этого действия');
        }

        const { name, description, price } = req.body;

        const images = req.files.map(file => file.buffer.toString('base64'));

        const result = await pool.query(
            'INSERT INTO products (name, description, images, price) VALUES ($1, $2, $3, $4) RETURNING *',
            [name, description, images, price]
        );

        const product = result.rows[0];
        res.status(201).json(product);
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/products', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM products');
        const products = result.rows;
        res.json(products);
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/add-to-cart', authenticateToken, async (req, res) => {
    try {
        const { productId, quantity } = req.body;
        const userId = req.user.id;

        const existingCart = await pool.query('SELECT * FROM shopping_carts WHERE user_id = $1', [
            userId,
        ]);

        if (existingCart.rows.length === 0) {
            const newCartResult = await pool.query(
                'INSERT INTO shopping_carts (user_id, products) VALUES ($1, $2) RETURNING *',
                [userId, [{ productId, quantity }]]
            );

            const newCart = newCartResult.rows[0];
            res.status(200).json(newCart);
        } else {
            const existingProducts = existingCart.rows[0].products;
            const updatedProducts = [...existingProducts, { productId, quantity }];

            const updatedCartResult = await pool.query(
                'UPDATE shopping_carts SET products = $1 WHERE user_id = $2 RETURNING *',
                [updatedProducts, userId]
            );

            const updatedCart = updatedCartResult.rows[0];
            res.status(200).json(updatedCart);
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/get-cart', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const result = await pool.query('SELECT * FROM shopping_carts WHERE user_id = $1', [userId]);
        const cart = result.rows[0];

        if (cart) {
            res.status(200).json(cart);
        } else {
            res.status(404).send('Корзина не найдена');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/calculate-total', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const result = await pool.query('SELECT * FROM shopping_carts WHERE user_id = $1', [userId]);
        const cart = result.rows[0];

        if (!cart) {
            return res.status(404).send('Корзина не найдена');
        }

        const products = cart.products || [];

        const total = products.reduce(async (acc, product) => {
            const productInfo = await pool.query('SELECT price FROM your_database_table_name WHERE id = $1', [product.productId]);
            const productPrice = productInfo.rows[0].price;
            acc += productPrice * product.quantity;
            return acc;
        }, 0);

        res.status(200).json({ total });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
