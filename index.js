const express = require('express');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const prisma = new PrismaClient();

app.use(express.json());

const SECRET = 'your_jwt_secret';

// Register user
app.post('/register', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });
    res.json(user);
  } catch (err) {
    next(err);
  }
});

// Login user
app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ userId: user.id }, SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    next(err);
  }
});

// Middleware for authentication
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token missing' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Create post
app.post('/posts', authenticate, async (req, res, next) => {
  try {
    const { title, content } = req.body;
    const post = await prisma.post.create({
      data: {
        title,
        content,
        authorId: req.user.userId,
      },
    });
    res.json(post);
  } catch (err) {
    next(err);
  }
});

// Get user posts
app.get('/posts', authenticate, async (req, res, next) => {
  try {
    const posts = await prisma.post.findMany({
      where: { authorId: req.user.userId },
    });
    res.json(posts);
  } catch (err) {
    next(err);
  }
});

// Update post
app.put('/posts/:id', authenticate, async (req, res, next) => {
  try {
    const { id } = req.params;
    const { title, content } = req.body;
    const post = await prisma.post.updateMany({
      where: {
        id: parseInt(id, 10),
        authorId: req.user.userId,
      },
      data: {
        title,
        content,
      },
    });
    if (post.count === 0) {
      return res.status(404).json({ error: 'Post not found or you are not the author' });
    }
    res.json(post);
  } catch (err) {
    next(err);
  }
});

// Delete post
app.delete('/posts/:id', authenticate, async (req, res, next) => {
  try {
    const { id } = req.params;
    const post = await prisma.post.deleteMany({
      where: {
        id: parseInt(id, 10),
        authorId: req.user.userId,
      },
    });
    if (post.count === 0) {
      return res.status(404).json({ error: 'Post not found or you are not the author' });
    }
    res.json({ message: 'Post deleted' });
  } catch (err) {
    next(err);
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
