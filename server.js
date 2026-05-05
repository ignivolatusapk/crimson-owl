const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// File upload setup
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// Database setup
const db = new sqlite3.Database('./ignivolatus.db');

// Initialize database tables
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            name TEXT,
            phone TEXT,
            user_type TEXT DEFAULT 'shop_owner',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Shops table
    db.run(`
        CREATE TABLE IF NOT EXISTS shops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            shop_name TEXT UNIQUE,
            slug TEXT UNIQUE,
            description TEXT,
            category TEXT,
            logo TEXT,
            banner TEXT,
            status TEXT DEFAULT 'pending',
            rent_due_date DATE,
            custom_domain TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);
    
    // Products table
    db.run(`
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER,
            name TEXT,
            description TEXT,
            price DECIMAL(10,2),
            stock INTEGER DEFAULT 0,
            image TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(shop_id) REFERENCES shops(id)
        )
    `);
    
    // Orders table
    db.run(`
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER,
            order_number TEXT UNIQUE,
            customer_name TEXT,
            customer_email TEXT,
            customer_phone TEXT,
            customer_address TEXT,
            total_amount DECIMAL(10,2),
            status TEXT DEFAULT 'pending',
            payment_status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(shop_id) REFERENCES shops(id)
        )
    `);
    
    // Order items table
    db.run(`
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            price DECIMAL(10,2),
            FOREIGN KEY(order_id) REFERENCES orders(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    `);
    
    // Rent payments table
    db.run(`
        CREATE TABLE IF NOT EXISTS rent_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER,
            amount DECIMAL(10,2),
            transaction_id TEXT UNIQUE,
            payment_method TEXT,
            status TEXT DEFAULT 'pending',
            paid_until DATE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(shop_id) REFERENCES shops(id)
        )
    `);
    
    // Create admin user if not exists
    db.get("SELECT * FROM users WHERE email = ?", ['admin@ignivolatus.com'], (err, user) => {
        if (!user) {
            const hashedPassword = bcrypt.hashSync('Admin123!', 10);
            db.run("INSERT INTO users (email, password, name, user_type) VALUES (?, ?, ?, ?)", 
                ['admin@ignivolatus.com', hashedPassword, 'Admin', 'landlord']);
        }
    });
});

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET || 'ignivolatus_secret_key_2024', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// ============ AUTH ROUTES ============
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name, phone, shop_name, description, category } = req.body;
    
    // Check if user exists
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (user) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run("INSERT INTO users (email, password, name, phone, user_type) VALUES (?, ?, ?, ?, ?)",
            [email, hashedPassword, name, phone, 'shop_owner'], function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            
            const userId = this.lastID;
            
            // Create shop
            const slug = shop_name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
            const rentDueDate = new Date();
            rentDueDate.setDate(rentDueDate.getDate() + 30);
            
            db.run(`INSERT INTO shops (user_id, shop_name, slug, description, category, status, rent_due_date) 
                    VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
                [userId, shop_name, slug, description, category, rentDueDate.toISOString().split('T')[0]],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    
                    const token = jwt.sign({ id: userId, email, type: 'shop_owner' }, 
                        process.env.JWT_SECRET || 'ignivolatus_secret_key_2024');
                    
                    res.json({ 
                        token, 
                        user: { id: userId, email, name, type: 'shop_owner' },
                        shop_id: this.lastID
                    });
                });
        });
    });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ id: user.id, email, type: user.user_type }, 
            process.env.JWT_SECRET || 'ignivolatus_secret_key_2024');
        
        res.json({ 
            token, 
            user: { id: user.id, email, name: user.name, type: user.user_type }
        });
    });
});

// ============ SHOP ROUTES ============
app.get('/api/shops', (req, res) => {
    db.all("SELECT * FROM shops WHERE status = 'active' ORDER BY created_at DESC", (err, shops) => {
        res.json(shops);
    });
});

app.get('/api/shops/:slug', (req, res) => {
    db.get("SELECT * FROM shops WHERE slug = ?", [req.params.slug], (err, shop) => {
        if (!shop) {
            return res.status(404).json({ error: 'Shop not found' });
        }
        
        db.all("SELECT * FROM products WHERE shop_id = ? AND stock > 0", [shop.id], (err, products) => {
            shop.products = products;
            res.json(shop);
        });
    });
});

app.get('/api/my-shop', authenticateToken, (req, res) => {
    db.get("SELECT * FROM shops WHERE user_id = ?", [req.user.id], (err, shop) => {
        if (!shop) {
            return res.status(404).json({ error: 'No shop found' });
        }
        
        db.all("SELECT * FROM products WHERE shop_id = ?", [shop.id], (err, products) => {
            db.all("SELECT * FROM orders WHERE shop_id = ? ORDER BY created_at DESC", [shop.id], (err, orders) => {
                res.json({ ...shop, products, orders });
            });
        });
    });
});

// ============ PRODUCT ROUTES ============
app.post('/api/products', authenticateToken, upload.single('image'), (req, res) => {
    const { name, description, price, stock } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : null;
    
    db.get("SELECT id FROM shops WHERE user_id = ?", [req.user.id], (err, shop) => {
        if (!shop) {
            return res.status(403).json({ error: 'No shop associated' });
        }
        
        db.run(`INSERT INTO products (shop_id, name, description, price, stock, image) 
                VALUES (?, ?, ?, ?, ?, ?)`,
            [shop.id, name, description, price, stock, image],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json({ id: this.lastID, message: 'Product created' });
            });
    });
});

app.put('/api/products/:id', authenticateToken, (req, res) => {
    const { name, description, price, stock } = req.body;
    
    db.run(`UPDATE products SET name = ?, description = ?, price = ?, stock = ? WHERE id = ?`,
        [name, description, price, stock, req.params.id], function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Product updated' });
        });
});

app.delete('/api/products/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM products WHERE id = ?", [req.params.id], function(err) {
        res.json({ message: 'Product deleted' });
    });
});

// ============ ORDER ROUTES ============
app.post('/api/orders', (req, res) => {
    const { shop_slug, items, customer_name, customer_email, customer_phone, customer_address } = req.body;
    
    db.get("SELECT id FROM shops WHERE slug = ?", [shop_slug], (err, shop) => {
        if (!shop) {
            return res.status(404).json({ error: 'Shop not found' });
        }
        
        const orderNumber = 'ORD-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
        let totalAmount = 0;
        
        // Calculate total
        items.forEach(item => {
            totalAmount += item.price * item.quantity;
        });
        
        db.run(`INSERT INTO orders (shop_id, order_number, customer_name, customer_email, customer_phone, customer_address, total_amount) 
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [shop.id, orderNumber, customer_name, customer_email, customer_phone, customer_address, totalAmount],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                
                const orderId = this.lastID;
                
                // Add order items
                items.forEach(item => {
                    db.run(`INSERT INTO order_items (order_id, product_id, quantity, price) 
                            VALUES (?, ?, ?, ?)`,
                        [orderId, item.product_id, item.quantity, item.price]);
                });
                
                res.json({ order_number: orderNumber, total_amount: totalAmount });
            });
    });
});

app.get('/api/orders/:shop_id', authenticateToken, (req, res) => {
    db.all("SELECT * FROM orders WHERE shop_id = ? ORDER BY created_at DESC", 
        [req.params.shop_id], (err, orders) => {
            res.json(orders);
        });
});

app.put('/api/orders/:id/status', authenticateToken, (req, res) => {
    const { status } = req.body;
    db.run("UPDATE orders SET status = ? WHERE id = ?", [status, req.params.id], function(err) {
        res.json({ message: 'Order status updated' });
    });
});

// ============ RENT PAYMENT ROUTES ============
app.post('/api/pay-rent', authenticateToken, (req, res) => {
    const { payment_method } = req.body;
    const transactionId = 'TXN-' + Date.now() + '-' + Math.floor(Math.random() * 10000);
    
    db.get("SELECT id, rent_due_date FROM shops WHERE user_id = ?", [req.user.id], (err, shop) => {
        if (!shop) {
            return res.status(404).json({ error: 'Shop not found' });
        }
        
        // Extend rent due date by 30 days
        const newDueDate = new Date();
        newDueDate.setDate(newDueDate.getDate() + 30);
        
        db.run(`INSERT INTO rent_payments (shop_id, amount, transaction_id, payment_method, status, paid_until) 
                VALUES (?, 500, ?, ?, 'completed', ?)`,
            [shop.id, transactionId, payment_method, newDueDate.toISOString().split('T')[0]],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                
                db.run("UPDATE shops SET rent_due_date = ?, status = 'active' WHERE id = ?", 
                    [newDueDate.toISOString().split('T')[0], shop.id]);
                
                res.json({ 
                    message: 'Rent paid successfully', 
                    paid_until: newDueDate,
                    transaction_id: transactionId
                });
            });
    });
});

// ============ ADMIN ROUTES ============
app.get('/api/admin/stats', authenticateToken, (req, res) => {
    if (req.user.type !== 'landlord') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    db.get("SELECT COUNT(*) as total_shops FROM shops", (err, totalShops) => {
        db.get("SELECT COUNT(*) as active_shops FROM shops WHERE status = 'active'", (err, activeShops) => {
            db.get("SELECT SUM(amount) as total_revenue FROM rent_payments WHERE status = 'completed'", (err, revenue) => {
                db.all("SELECT * FROM shops ORDER BY created_at DESC", (err, shops) => {
                    res.json({
                        total_shops: totalShops.total_shops,
                        active_shops: activeShops.active_shops,
                        total_revenue: revenue.total_revenue || 0,
                        shops: shops
                    });
                });
            });
        });
    });
});

app.put('/api/admin/shops/:id/status', authenticateToken, (req, res) => {
    if (req.user.type !== 'landlord') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { status } = req.body;
    db.run("UPDATE shops SET status = ? WHERE id = ?", [status, req.params.id], function(err) {
        res.json({ message: 'Shop status updated' });
    });
});

// Serve frontend for custom domains
app.get('*', (req, res) => {
    const host = req.get('host');
    const subdomain = host.split('.')[0];
    
    // Check if it's a custom shop domain
    if (subdomain !== 'www' && subdomain !== 'ignivolatus') {
        db.get("SELECT * FROM shops WHERE slug = ? OR custom_domain = ?", [subdomain, host], (err, shop) => {
            if (shop && shop.status === 'active') {
                res.sendFile(path.join(__dirname, 'public', 'shop.html'));
            } else {
                res.sendFile(path.join(__dirname, 'public', 'index.html'));
            }
        });
    } else {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Ignivolatus Store running on port ${PORT}`);
    console.log(`📊 Admin dashboard: http://localhost:${PORT}/admin.html`);
    console.log(`🏪 Shop dashboard: http://localhost:${PORT}/dashboard.html`);
});