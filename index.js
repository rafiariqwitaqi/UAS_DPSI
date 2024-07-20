const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./firebase');
const { verifyToken, verifyRole } = require('./auth');
const cors = require('cors');
const dotenv = require('dotenv');
const app = express();
app.use(express.json());
app.use(cors({
  origin: '*', // Updated origin
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
dotenv.config();

const PORT = process.env.PORT || 3000;

// Add product
app.post('/products', [verifyToken, verifyRole('admin')], async (req, res) => {
  const { id, name, price, stock } = req.body;

  if (!id || !name || !price || !stock) {
    return res.status(400).send({ message: 'Please provide id, name, price, and stock for the product.' });
  }

  try {
    const productRef = db.collection('products').doc(id);
    const productDoc = await productRef.get();

    if (productDoc.exists) {
      return res.status(400).send({ message: 'Product already exists.' });
    }

    await productRef.set({
      id,
      name,
      price,
      stock
    });

    res.status(201).send({ message: 'Product added successfully' });
  } catch (error) {
    res.status(500).send({ message: 'Error adding product, please try again later.' });
  }
});

// Add order
app.post('/orders', [verifyToken, verifyRole('admin')], async (req, res) => {
  const { orderId, username, productId, quantity, totalPrice } = req.body;

  if (!orderId || !username || !productId || !quantity || !totalPrice) {
    return res.status(400).send({ message: 'Please provide orderId, username, productId, quantity, and totalPrice.' });
  }

  try {
    const orderRef = db.collection('orders').doc(orderId);
    const orderDoc = await orderRef.get();

    if (orderDoc.exists) {
      return res.status(400).send({ message: 'Order already exists.' });
    }

    await orderRef.set({
      orderId,
      username,
      productId,
      quantity,
      totalPrice
    });

    res.status(201).send({ message: 'Order added successfully' });
  } catch (error) {
    res.status(500).send({ message: 'Error adding order, please try again later.' });
  }
});

// Add payment
app.post('/payments', [verifyToken, verifyRole('admin')], async (req, res) => {
  const { paymentId, orderId, amount, status } = req.body;

  if (!paymentId || !orderId || !amount || !status) {
    return res.status(400).send({ message: 'Please provide paymentId, orderId, amount, and status.' });
  }

  try {
    const paymentRef = db.collection('payments').doc(paymentId);
    const paymentDoc = await paymentRef.get();

    if (paymentDoc.exists) {
      return res.status(400).send({ message: 'Payment already exists.' });
    }

    await paymentRef.set({
      paymentId,
      orderId,
      amount,
      status
    });

    res.status(201).send({ message: 'Payment added successfully' });
  } catch (error) {
    res.status(500).send({ message: 'Error adding payment, please try again later.' });
  }
});

// Register route
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).send({ message: 'Please provide username, password, and role.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store user in Firestore
    const userRef = db.collection('users').doc(username);
    const userDoc = await userRef.get();

    if (userDoc.exists) {
      return res.status(400).send({ message: 'User already exists.' });
    }

    await userRef.set({
      username,
      password: hashedPassword,
      role
    });

    const token = jwt.sign({ id: username, role }, 'rafirafi', { expiresIn: 86400 });
    res.status(201).send({ message: 'User Registered' });
  } catch (error) {
    res.status(500).send({ message: 'Error registering user, please try again later.' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const userRef = db.collection('users').doc(username);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).send({ message: 'User not found.' });
    }

    const user = userDoc.data();

    const passwordIsValid = await bcrypt.compare(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).send({ message: 'Invalid password.' });
    }

    const token = jwt.sign({ id: user.username, role: user.role }, 'rafirafi', { expiresIn: 86400 });

    res.status(200).send({ token });
  } catch (error) {
    res.status(500).send({ message: 'Error logging in, please try again later.' });
  }
});

// Get product data
app.get('/products', [verifyToken, verifyRole('admin')], async (req, res) => {
  try {
    const productsSnapshot = await db.collection('products').get();
    const products = productsSnapshot.docs.map(doc => doc.data());
    res.status(200).send(products);
  } catch (error) {
    res.status(500).send({ message: 'Data produk tidak dapat diambil saat ini, silakan coba lagi nanti.' });
  }
});

// Get orders data
app.get('/orders', [verifyToken, verifyRole('admin')], async (req, res) => {
  try {
    const ordersSnapshot = await db.collection('orders').get();
    const orders = ordersSnapshot.docs.map(doc => doc.data());
    res.status(200).send(orders);
  } catch (error) {
    res.status(500).send({ message: 'Data pemesanan tidak dapat diambil saat ini, silakan coba lagi nanti.' });
  }
});

// Get payment data
app.get('/payments', [verifyToken, verifyRole('admin')], async (req, res) => {
  try {
    const paymentsSnapshot = await db.collection('payments').get();
    const payments = paymentsSnapshot.docs.map(doc => doc.data());
    res.status(200).send(payments);
  } catch (error) {
    res.status(500).send({ message: 'Data pembayaran tidak dapat diambil saat ini, silakan coba lagi nanti.' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
