require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getChatbotResponse } = require('./ai_service');

const app = express();

app.use(cors());
app.use(express.json());

const pool = require('./database');

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error('Set JWT_SECRET before starting the server.');
}

// --------------------------------------------------
// PROCESS DIAGNOSTIC LOGS
// --------------------------------------------------

process.on('uncaughtException', (error) => {
  console.error('UNCAUGHT EXCEPTION:', error);
});

process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED PROMISE REJECTION:', reason);
});

// --------------------------------------------------
// AUTHENTICATION HELPERS
// --------------------------------------------------

function getTokenFromRequest(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return null;
  }
  return header.substring(7);
}

function authenticateUser(req, res, next) {
  const token = getTokenFromRequest(req);

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required. Please log in.',
    });
  }

  if (!JWT_SECRET) {
    return res.status(500).json({
      success: false,
      message: 'Server authentication is not configured.',
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (!decoded.userId) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token.',
      });
    }

    req.user = {
      userId: decoded.userId,
      email: decoded.email,
    };

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token. Please log in again.',
    });
  }
}

async function authenticateAdmin(req, res, next) {
  const token = getTokenFromRequest(req);

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required.',
    });
  }

  if (!JWT_SECRET) {
    return res.status(500).json({
      success: false,
      message: 'Server authentication is not configured.',
    });
  }

  try {
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (_) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token.',
      });
    }

    const result = await pool.query(
      'SELECT user_id FROM admin_access WHERE user_id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({
        success: false,
        message: 'Admin access denied.',
      });
    }

    req.admin = { userId: decoded.userId };
    req.user = { userId: decoded.userId, email: decoded.email };
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    return res.status(500).json({
      success: false,
      message: 'Admin authentication failed.',
    });
  }
}

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({
      success: true,
      message: 'FinanceFlow backend is running',
      database: 'Connected',
      time: result.rows[0].now,
    });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({
      success: false,
      message: 'Backend is running but database connection failed.',
    });
  }
});

// --------------------------------------------------
// REGISTER USER
// --------------------------------------------------

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;

    if (
      !name?.trim() ||
      !email?.trim() ||
      !mobile?.trim() ||
      typeof password !== 'string' ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: 'Name, email, mobile and password are required.',
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters.',
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedMobile = mobile.trim();

    const existingUser = await pool.query(
      `SELECT id FROM users WHERE LOWER(email) = $1 OR mobile = $2`,
      [normalizedEmail, normalizedMobile]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Email or mobile number is already registered.',
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const userId = crypto.randomUUID();

    const client = await pool.connect();
    let result;
    try {
      await client.query('BEGIN');
      result = await client.query(
        `INSERT INTO users (id, name, email, mobile, password_hash)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, name, email, mobile, created_at`,
        [userId, name.trim(), normalizedEmail, normalizedMobile, passwordHash]
      );
      for (const table of ['notification_settings', 'user_settings', 'security_settings']) {
        await client.query(
          `INSERT INTO ${table} (id, user_id) VALUES ($1, $2)`,
          [crypto.randomUUID(), userId]
        );
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    return res.status(201).json({
      success: true,
      message: 'User registered successfully.',
      user: result.rows[0],
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === '23505') {
      return res.status(409).json({
        success: false,
        message: 'Email or mobile number is already registered.',
      });
    }
    return res.status(500).json({
      success: false,
      message: 'Registration failed.',
    });
  }
});

// --------------------------------------------------
// LOGIN USER
// --------------------------------------------------

app.post('/api/auth/login', async (req, res) => {
  try {
    const { emailOrMobile, password } = req.body;

    if (!emailOrMobile || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email/mobile and password are required.',
      });
    }

    if (!JWT_SECRET) {
      return res.status(500).json({
        success: false,
        message: 'Server authentication is not configured.',
      });
    }

    const loginValue = String(emailOrMobile).trim();

    const result = await pool.query(
      `SELECT id, name, email, mobile, password_hash, is_active
       FROM users
       WHERE LOWER(email) = LOWER($1) OR mobile = $1
       LIMIT 1`,
      [loginValue]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email/mobile or password.',
      });
    }

    const user = result.rows[0];

    if (user.is_active === false) {
      return res.status(403).json({
        success: false,
        message: 'Account has been deactivated. Please contact an administrator.',
      });
    }

    const passwordMatches = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email/mobile or password.',
      });
    }

    const adminCheck = await pool.query(
      'SELECT user_id FROM admin_access WHERE user_id = $1',
      [user.id]
    );
    const isAdmin = adminCheck.rows.length > 0;

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Optional: Record login session
    pool.query(
      `INSERT INTO login_sessions (id, user_id, ip_address, user_agent)
       VALUES ($1, $2, $3, $4)`,
      [crypto.randomUUID(), user.id, req.ip || 'unknown', req.headers['user-agent'] || 'app']
    ).catch(() => {});

    return res.json({
      success: true,
      message: 'Login successful.',
      token,
      isAdmin,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        mobile: user.mobile,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      success: false,
      message: 'Login failed.',
    });
  }
});

// --------------------------------------------------
// GET CURRENT USER AUTH & PROFILE
// --------------------------------------------------

app.get('/api/auth/me', authenticateUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, mobile, date_of_birth, gender,
              country, address, city, state, pin_code, occupation,
              employment_type, monthly_income, preferred_currency,
              language, date_format, email_verified, mobile_verified,
              is_active, created_at, updated_at
       FROM users WHERE id = $1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const adminCheck = await pool.query(
      'SELECT user_id FROM admin_access WHERE user_id = $1',
      [req.user.userId]
    );

    return res.json({
      success: true,
      user: result.rows[0],
      isAdmin: adminCheck.rows.length > 0,
    });
  } catch (error) {
    console.error('Auth check error:', error);
    return res.status(500).json({ success: false, message: 'Session check failed.' });
  }
});

app.get('/api/users/profile', authenticateUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, mobile, date_of_birth, gender,
              country, address, city, state, pin_code, occupation,
              employment_type, monthly_income, preferred_currency,
              language, date_format, email_verified, mobile_verified,
              is_active, created_at, updated_at
       FROM users WHERE id = $1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.json({
      success: true,
      user: result.rows[0],
    });
  } catch (error) {
    console.error('Get profile error:', error);
    return res.status(500).json({ success: false, message: 'Could not load profile.' });
  }
});

// --------------------------------------------------
// CHANGE PASSWORD
// --------------------------------------------------

app.post('/api/auth/change-password', authenticateUser, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required.',
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters.',
      });
    }

    const userRes = await pool.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (userRes.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const matches = await bcrypt.compare(currentPassword, userRes.rows[0].password_hash);
    if (!matches) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect.',
      });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [newHash, req.user.userId]
    );

    return res.json({
      success: true,
      message: 'Password changed successfully.',
    });
  } catch (error) {
    console.error('Change password error:', error);
    return res.status(500).json({ success: false, message: 'Password change failed.' });
  }
});

// --------------------------------------------------
// UPDATE USER PROFILE
// --------------------------------------------------

app.put('/api/users/:userId/profile', authenticateUser, async (req, res) => {
  try {
    const { userId } = req.params;

    if (req.user.userId !== userId) {
      return res.status(403).json({
        success: false,
        message: 'You cannot update another user profile.',
      });
    }

    const {
      name, email, mobile, dateOfBirth, gender, country,
      address, city, state, pinCode, occupation,
      employmentType, monthlyIncome, preferredCurrency,
      language, dateFormat,
    } = req.body;

    if (!name || !email || !mobile) {
      return res.status(400).json({
        success: false,
        message: 'Name, email and mobile are required.',
      });
    }

    const result = await pool.query(
      `UPDATE users
       SET
         name = $1,
         email = $2,
         mobile = $3,
         date_of_birth = $4,
         gender = $5,
         country = $6,
         address = $7,
         city = $8,
         state = $9,
         pin_code = $10,
         occupation = $11,
         employment_type = $12,
         monthly_income = $13,
         preferred_currency = $14,
         language = $15,
         date_format = $16,
         updated_at = CURRENT_TIMESTAMP
       WHERE id = $17
       RETURNING
         id, name, email, mobile, date_of_birth, gender,
         country, address, city, state, pin_code,
         occupation, employment_type, monthly_income,
         preferred_currency, language, date_format,
         email_verified, mobile_verified, updated_at`,
      [
        name,
        email.trim().toLowerCase(),
        mobile.trim(),
        dateOfBirth || null,
        gender || null,
        country || null,
        address || null,
        city || null,
        state || null,
        pinCode || null,
        occupation || null,
        employmentType || null,
        monthlyIncome ?? null,
        preferredCurrency || 'INR',
        language || 'English',
        dateFormat || 'DD/MM/YYYY',
        userId,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.json({
      success: true,
      message: 'Profile updated successfully.',
      user: result.rows[0],
    });
  } catch (error) {
    console.error('Profile update error:', error);
    if (error.code === '23505') {
      return res.status(409).json({
        success: false,
        message: 'This email or mobile is already registered.',
      });
    }
    return res.status(500).json({ success: false, message: 'Profile update failed.' });
  }
});

// --------------------------------------------------
// EXPENSES APIs
// --------------------------------------------------

// Create an expense
app.post('/api/expenses', authenticateUser, async (req, res) => {
  try {
    const { amount, category, expense_date, expenseDate, note } = req.body;
    const date = expense_date || expenseDate;

    if (
      amount === undefined ||
      amount === null ||
      !Number.isFinite(Number(amount)) ||
      Number(amount) <= 0 ||
      !category ||
      !date ||
      Number.isNaN(Date.parse(date))
    ) {
      return res.status(400).json({
        success: false,
        message: 'A valid amount, category and expense date are required.',
      });
    }

    const result = await pool.query(
      `INSERT INTO expenses (
        id, user_id, amount, category, expense_date, note
      )
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, user_id, amount, category, expense_date, note, created_at`,
      [
        crypto.randomUUID(),
        req.user.userId,
        Number(amount),
        String(category).trim(),
        date,
        note ? String(note).trim() : null,
      ]
    );

    return res.status(201).json({
      success: true,
      message: 'Expense saved successfully.',
      expense: result.rows[0],
    });
  } catch (error) {
    console.error('Create expense error:', error);
    return res.status(500).json({ success: false, message: 'Could not save expense.' });
  }
});

// Get user's expenses
app.get('/api/expenses', authenticateUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, user_id, amount, category, expense_date, note, created_at
       FROM expenses
       WHERE user_id = $1
       ORDER BY expense_date DESC, created_at DESC`,
      [req.user.userId]
    );

    return res.json({
      success: true,
      expenses: result.rows,
    });
  } catch (error) {
    console.error('Get expenses error:', error);
    return res.status(500).json({ success: false, message: 'Could not load expenses.' });
  }
});

// Update an expense
app.put('/api/expenses/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount, category, expense_date, expenseDate, note } = req.body;
    const date = expense_date || expenseDate;

    if (
      amount === undefined ||
      amount === null ||
      !Number.isFinite(Number(amount)) ||
      Number(amount) <= 0 ||
      !category ||
      !date ||
      Number.isNaN(Date.parse(date))
    ) {
      return res.status(400).json({
        success: false,
        message: 'A valid amount, category and expense date are required.',
      });
    }

    const result = await pool.query(
      `UPDATE expenses
       SET amount = $1, category = $2, expense_date = $3, note = $4
       WHERE id = $5 AND user_id = $6
       RETURNING id, user_id, amount, category, expense_date, note, created_at`,
      [
        Number(amount),
        String(category).trim(),
        date,
        note ? String(note).trim() : null,
        id,
        req.user.userId,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Expense not found.' });
    }

    return res.json({
      success: true,
      message: 'Expense updated successfully.',
      expense: result.rows[0],
    });
  } catch (error) {
    console.error('Update expense error:', error);
    return res.status(500).json({ success: false, message: 'Could not update expense.' });
  }
});

// Delete an expense
app.delete('/api/expenses/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'DELETE FROM expenses WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Expense not found.' });
    }

    return res.json({ success: true, message: 'Expense deleted successfully.' });
  } catch (error) {
    console.error('Delete expense error:', error);
    return res.status(500).json({ success: false, message: 'Could not delete expense.' });
  }
});

// --------------------------------------------------
// INCOMES APIs
// --------------------------------------------------

// Create an income
app.post('/api/incomes', authenticateUser, async (req, res) => {
  try {
    const { amount, category, income_date, incomeDate, note } = req.body;
    const date = income_date || incomeDate;

    if (
      amount === undefined ||
      amount === null ||
      !Number.isFinite(Number(amount)) ||
      Number(amount) <= 0 ||
      !category ||
      !date ||
      Number.isNaN(Date.parse(date))
    ) {
      return res.status(400).json({
        success: false,
        message: 'A valid amount, category and income date are required.',
      });
    }

    const result = await pool.query(
      `INSERT INTO incomes (
        id, user_id, amount, category, income_date, note
      )
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, user_id, amount, category, income_date, note, created_at`,
      [
        crypto.randomUUID(),
        req.user.userId,
        Number(amount),
        String(category).trim(),
        date,
        note ? String(note).trim() : null,
      ]
    );

    return res.status(201).json({
      success: true,
      message: 'Income saved successfully.',
      income: result.rows[0],
    });
  } catch (error) {
    console.error('Create income error:', error);
    return res.status(500).json({ success: false, message: 'Could not save income.' });
  }
});

// Get user's incomes
app.get('/api/incomes', authenticateUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, user_id, amount, category, income_date, note, created_at
       FROM incomes
       WHERE user_id = $1
       ORDER BY income_date DESC, created_at DESC`,
      [req.user.userId]
    );

    return res.json({
      success: true,
      incomes: result.rows,
    });
  } catch (error) {
    console.error('Get incomes error:', error);
    return res.status(500).json({ success: false, message: 'Could not load incomes.' });
  }
});

// Update an income
app.put('/api/incomes/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount, category, income_date, incomeDate, note } = req.body;
    const date = income_date || incomeDate;

    if (
      amount === undefined ||
      amount === null ||
      !Number.isFinite(Number(amount)) ||
      Number(amount) <= 0 ||
      !category ||
      !date ||
      Number.isNaN(Date.parse(date))
    ) {
      return res.status(400).json({
        success: false,
        message: 'A valid amount, category and income date are required.',
      });
    }

    const result = await pool.query(
      `UPDATE incomes
       SET amount = $1, category = $2, income_date = $3, note = $4
       WHERE id = $5 AND user_id = $6
       RETURNING id, user_id, amount, category, income_date, note, created_at`,
      [
        Number(amount),
        String(category).trim(),
        date,
        note ? String(note).trim() : null,
        id,
        req.user.userId,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Income not found.' });
    }

    return res.json({
      success: true,
      message: 'Income updated successfully.',
      income: result.rows[0],
    });
  } catch (error) {
    console.error('Update income error:', error);
    return res.status(500).json({ success: false, message: 'Could not update income.' });
  }
});

// Delete an income
app.delete('/api/incomes/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'DELETE FROM incomes WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Income not found.' });
    }

    return res.json({ success: true, message: 'Income deleted successfully.' });
  } catch (error) {
    console.error('Delete income error:', error);
    return res.status(500).json({ success: false, message: 'Could not delete income.' });
  }
});

// --------------------------------------------------
// BUDGETS APIs
// --------------------------------------------------

// Get user's budgets
app.get('/api/budgets', authenticateUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, user_id, category, amount, budget_month, created_at
       FROM budgets
       WHERE user_id = $1
       ORDER BY budget_month DESC, created_at DESC`,
      [req.user.userId]
    );

    return res.json({ success: true, budgets: result.rows });
  } catch (error) {
    console.error('Get budgets error:', error);
    return res.status(500).json({ success: false, message: 'Could not load budgets.' });
  }
});

// Create or update budget for month/category
app.post('/api/budgets', authenticateUser, async (req, res) => {
  try {
    const { category, amount, budget_month, budgetMonth } = req.body;
    const month = budget_month || budgetMonth || new Date().toISOString().substring(0, 10);

    if (!category || amount === undefined || Number(amount) <= 0) {
      return res.status(400).json({
        success: false,
        message: 'A valid category and positive budget amount are required.',
      });
    }

    const result = await pool.query(
      `INSERT INTO budgets (id, user_id, category, amount, budget_month)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, user_id, category, amount, budget_month, created_at`,
      [
        crypto.randomUUID(),
        req.user.userId,
        String(category).trim(),
        Number(amount),
        month,
      ]
    );

    return res.status(201).json({
      success: true,
      message: 'Budget saved successfully.',
      budget: result.rows[0],
    });
  } catch (error) {
    console.error('Create budget error:', error);
    return res.status(500).json({ success: false, message: 'Could not save budget.' });
  }
});

// Update budget
app.put('/api/budgets/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { category, amount, budget_month, budgetMonth } = req.body;
    const month = budget_month || budgetMonth;

    const result = await pool.query(
      `UPDATE budgets
       SET category = COALESCE($1, category),
           amount = COALESCE($2, amount),
           budget_month = COALESCE($3, budget_month)
       WHERE id = $4 AND user_id = $5
       RETURNING id, user_id, category, amount, budget_month, created_at`,
      [
        category ? String(category).trim() : null,
        amount !== undefined ? Number(amount) : null,
        month || null,
        id,
        req.user.userId,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Budget not found.' });
    }

    return res.json({
      success: true,
      message: 'Budget updated successfully.',
      budget: result.rows[0],
    });
  } catch (error) {
    console.error('Update budget error:', error);
    return res.status(500).json({ success: false, message: 'Could not update budget.' });
  }
});

// Delete budget
app.delete('/api/budgets/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'DELETE FROM budgets WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Budget not found.' });
    }

    return res.json({ success: true, message: 'Budget deleted successfully.' });
  } catch (error) {
    console.error('Delete budget error:', error);
    return res.status(500).json({ success: false, message: 'Could not delete budget.' });
  }
});

// --------------------------------------------------
// SAVINGS GOALS APIs
// --------------------------------------------------

// Get user's savings goals
app.get('/api/savings-goals', authenticateUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, user_id, name, target_amount, saved_amount, target_date, description, created_at, updated_at
       FROM savings_goals
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.userId]
    );

    return res.json({ success: true, goals: result.rows });
  } catch (error) {
    console.error('Get savings goals error:', error);
    return res.status(500).json({ success: false, message: 'Could not load savings goals.' });
  }
});

// Create savings goal
app.post('/api/savings-goals', authenticateUser, async (req, res) => {
  try {
    const { name, target_amount, targetAmount, saved_amount, savedAmount, target_date, targetDate, description } = req.body;
    const target = target_amount || targetAmount;
    const saved = saved_amount || savedAmount || 0;
    const tDate = target_date || targetDate || null;

    if (!name?.trim() || !target || Number(target) <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Goal name and target amount are required.',
      });
    }

    const result = await pool.query(
      `INSERT INTO savings_goals (id, user_id, name, target_amount, saved_amount, target_date, description)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, user_id, name, target_amount, saved_amount, target_date, description, created_at, updated_at`,
      [
        crypto.randomUUID(),
        req.user.userId,
        name.trim(),
        Number(target),
        Number(saved),
        tDate,
        description ? description.trim() : null,
      ]
    );

    return res.status(201).json({
      success: true,
      message: 'Savings goal created successfully.',
      goal: result.rows[0],
    });
  } catch (error) {
    console.error('Create savings goal error:', error);
    return res.status(500).json({ success: false, message: 'Could not create savings goal.' });
  }
});

// Contribute to savings goal
app.post('/api/savings-goals/:id/contribute', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount } = req.body;

    if (!amount || Number(amount) <= 0) {
      return res.status(400).json({ success: false, message: 'Contribution amount must be greater than zero.' });
    }

    const result = await pool.query(
      `UPDATE savings_goals
       SET saved_amount = saved_amount + $1,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $2 AND user_id = $3
       RETURNING id, user_id, name, target_amount, saved_amount, target_date, description, updated_at`,
      [Number(amount), id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Savings goal not found.' });
    }

    return res.json({
      success: true,
      message: 'Contribution recorded successfully.',
      goal: result.rows[0],
    });
  } catch (error) {
    console.error('Contribute to savings goal error:', error);
    return res.status(500).json({ success: false, message: 'Could not record contribution.' });
  }
});

// Update savings goal
app.put('/api/savings-goals/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, target_amount, targetAmount, saved_amount, savedAmount, target_date, targetDate, description } = req.body;
    const target = target_amount || targetAmount;
    const saved = saved_amount || savedAmount;
    const tDate = target_date || targetDate;

    const result = await pool.query(
      `UPDATE savings_goals
       SET name = COALESCE($1, name),
           target_amount = COALESCE($2, target_amount),
           saved_amount = COALESCE($3, saved_amount),
           target_date = COALESCE($4, target_date),
           description = COALESCE($5, description),
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $6 AND user_id = $7
       RETURNING id, user_id, name, target_amount, saved_amount, target_date, description, updated_at`,
      [
        name ? name.trim() : null,
        target !== undefined ? Number(target) : null,
        saved !== undefined ? Number(saved) : null,
        tDate || null,
        description !== undefined ? description : null,
        id,
        req.user.userId,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Savings goal not found.' });
    }

    return res.json({
      success: true,
      message: 'Savings goal updated successfully.',
      goal: result.rows[0],
    });
  } catch (error) {
    console.error('Update savings goal error:', error);
    return res.status(500).json({ success: false, message: 'Could not update savings goal.' });
  }
});

// Delete savings goal
app.delete('/api/savings-goals/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'DELETE FROM savings_goals WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Savings goal not found.' });
    }

    return res.json({ success: true, message: 'Savings goal deleted successfully.' });
  } catch (error) {
    console.error('Delete savings goal error:', error);
    return res.status(500).json({ success: false, message: 'Could not delete savings goal.' });
  }
});

// --------------------------------------------------
// LOANS APIs
// --------------------------------------------------

// Get user's loans
app.get('/api/loans', authenticateUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, user_id, name, loan_amount, monthly_emi, tenure_months, paid_months,
              interest_rate, start_date, lender_name, loan_type, created_at, updated_at
       FROM loans
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.userId]
    );

    return res.json({ success: true, loans: result.rows });
  } catch (error) {
    console.error('Get loans error:', error);
    return res.status(500).json({ success: false, message: 'Could not load loans.' });
  }
});

// Create loan
app.post('/api/loans', authenticateUser, async (req, res) => {
  try {
    const {
      name, loan_amount, loanAmount, monthly_emi, monthlyEmi,
      tenure_months, tenureMonths, paid_months, paidMonths,
      interest_rate, interestRate, start_date, startDate,
      lender_name, lenderName, loan_type, loanType
    } = req.body;

    const amount = loan_amount || loanAmount;
    const emi = monthly_emi || monthlyEmi;
    const tenure = tenure_months || tenureMonths;
    const paid = paid_months !== undefined ? paid_months : (paidMonths !== undefined ? paidMonths : 0);

    if (!name?.trim() || !amount || Number(amount) <= 0 || !emi || !tenure) {
      return res.status(400).json({
        success: false,
        message: 'Loan name, amount, monthly EMI, and tenure are required.',
      });
    }

    const result = await pool.query(
      `INSERT INTO loans (
        id, user_id, name, loan_amount, monthly_emi, tenure_months, paid_months,
        interest_rate, start_date, lender_name, loan_type
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id, user_id, name, loan_amount, monthly_emi, tenure_months, paid_months,
                interest_rate, start_date, lender_name, loan_type, created_at, updated_at`,
      [
        crypto.randomUUID(),
        req.user.userId,
        name.trim(),
        Number(amount),
        Number(emi),
        Number(tenure),
        Number(paid),
        interest_rate || interestRate || 0,
        start_date || startDate || new Date().toISOString().substring(0, 10),
        lender_name || lenderName || null,
        loan_type || loanType || 'borrowed',
      ]
    );

    return res.status(201).json({
      success: true,
      message: 'Loan added successfully.',
      loan: result.rows[0],
    });
  } catch (error) {
    console.error('Create loan error:', error);
    return res.status(500).json({ success: false, message: 'Could not create loan record.' });
  }
});

// Record EMI payment
app.post('/api/loans/:id/pay-emi', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE loans
       SET paid_months = LEAST(tenure_months, paid_months + 1),
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1 AND user_id = $2
       RETURNING id, user_id, name, loan_amount, monthly_emi, tenure_months, paid_months, updated_at`,
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Loan not found.' });
    }

    return res.json({
      success: true,
      message: 'EMI payment recorded successfully.',
      loan: result.rows[0],
    });
  } catch (error) {
    console.error('Pay EMI error:', error);
    return res.status(500).json({ success: false, message: 'Could not record EMI payment.' });
  }
});

// Update loan
app.put('/api/loans/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, loan_amount, loanAmount, monthly_emi, monthlyEmi,
      tenure_months, tenureMonths, paid_months, paidMonths,
      interest_rate, interestRate, lender_name, lenderName
    } = req.body;

    const amount = loan_amount || loanAmount;
    const emi = monthly_emi || monthlyEmi;
    const tenure = tenure_months || tenureMonths;
    const paid = paid_months !== undefined ? paid_months : paidMonths;

    const result = await pool.query(
      `UPDATE loans
       SET name = COALESCE($1, name),
           loan_amount = COALESCE($2, loan_amount),
           monthly_emi = COALESCE($3, monthly_emi),
           tenure_months = COALESCE($4, tenure_months),
           paid_months = COALESCE($5, paid_months),
           interest_rate = COALESCE($6, interest_rate),
           lender_name = COALESCE($7, lender_name),
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $8 AND user_id = $9
       RETURNING id, user_id, name, loan_amount, monthly_emi, tenure_months, paid_months,
                 interest_rate, lender_name, updated_at`,
      [
        name ? name.trim() : null,
        amount !== undefined ? Number(amount) : null,
        emi !== undefined ? Number(emi) : null,
        tenure !== undefined ? Number(tenure) : null,
        paid !== undefined ? Number(paid) : null,
        interest_rate !== undefined ? Number(interest_rate) : (interestRate !== undefined ? Number(interestRate) : null),
        lender_name || lenderName || null,
        id,
        req.user.userId,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Loan not found.' });
    }

    return res.json({
      success: true,
      message: 'Loan updated successfully.',
      loan: result.rows[0],
    });
  } catch (error) {
    console.error('Update loan error:', error);
    return res.status(500).json({ success: false, message: 'Could not update loan.' });
  }
});

// Delete loan
app.delete('/api/loans/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'DELETE FROM loans WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Loan not found.' });
    }

    return res.json({ success: true, message: 'Loan deleted successfully.' });
  } catch (error) {
    console.error('Delete loan error:', error);
    return res.status(500).json({ success: false, message: 'Could not delete loan.' });
  }
});

// --------------------------------------------------
// SETTINGS APIs
// --------------------------------------------------

// Get all user settings
app.get('/api/settings', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.userId;

    let [notifRes, appRes, secRes] = await Promise.all([
      pool.query('SELECT * FROM notification_settings WHERE user_id = $1', [userId]),
      pool.query('SELECT * FROM user_settings WHERE user_id = $1', [userId]),
      pool.query('SELECT biometric_enabled, two_factor_enabled, recovery_email, recovery_mobile FROM security_settings WHERE user_id = $1', [userId]),
    ]);

    // Ensure records exist
    if (notifRes.rows.length === 0) {
      await pool.query('INSERT INTO notification_settings (id, user_id) VALUES ($1, $2)', [crypto.randomUUID(), userId]);
      notifRes = await pool.query('SELECT * FROM notification_settings WHERE user_id = $1', [userId]);
    }
    if (appRes.rows.length === 0) {
      await pool.query('INSERT INTO user_settings (id, user_id) VALUES ($1, $2)', [crypto.randomUUID(), userId]);
      appRes = await pool.query('SELECT * FROM user_settings WHERE user_id = $1', [userId]);
    }
    if (secRes.rows.length === 0) {
      await pool.query('INSERT INTO security_settings (id, user_id) VALUES ($1, $2)', [crypto.randomUUID(), userId]);
      secRes = await pool.query('SELECT biometric_enabled, two_factor_enabled, recovery_email, recovery_mobile FROM security_settings WHERE user_id = $1', [userId]);
    }

    return res.json({
      success: true,
      notifications: notifRes.rows[0],
      appearance: appRes.rows[0],
      security: secRes.rows[0],
    });
  } catch (error) {
    console.error('Get settings error:', error);
    return res.status(500).json({ success: false, message: 'Could not load settings.' });
  }
});

// Update notification settings
app.put('/api/settings/notifications', authenticateUser, async (req, res) => {
  try {
    const {
      expense_alerts, income_alerts, budget_alerts,
      savings_goal_alerts, loan_emi_alerts, security_alerts, promotional_alerts
    } = req.body;

    const result = await pool.query(
      `INSERT INTO notification_settings (
        id, user_id, expense_alerts, income_alerts, budget_alerts,
        savings_goal_alerts, loan_emi_alerts, security_alerts, promotional_alerts, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id) DO UPDATE
      SET expense_alerts = COALESCE($3, notification_settings.expense_alerts),
          income_alerts = COALESCE($4, notification_settings.income_alerts),
          budget_alerts = COALESCE($5, notification_settings.budget_alerts),
          savings_goal_alerts = COALESCE($6, notification_settings.savings_goal_alerts),
          loan_emi_alerts = COALESCE($7, notification_settings.loan_emi_alerts),
          security_alerts = COALESCE($8, notification_settings.security_alerts),
          promotional_alerts = COALESCE($9, notification_settings.promotional_alerts),
          updated_at = CURRENT_TIMESTAMP
      RETURNING *`,
      [
        crypto.randomUUID(), req.user.userId,
        expense_alerts ?? true, income_alerts ?? true, budget_alerts ?? true,
        savings_goal_alerts ?? true, loan_emi_alerts ?? true, security_alerts ?? true,
        promotional_alerts ?? false
      ]
    );

    return res.json({ success: true, message: 'Notification preferences saved.', settings: result.rows[0] });
  } catch (error) {
    console.error('Update notifications error:', error);
    return res.status(500).json({ success: false, message: 'Could not save notification preferences.' });
  }
});

// Update appearance settings
app.put('/api/settings/appearance', authenticateUser, async (req, res) => {
  try {
    const { theme, language, currency, date_format } = req.body;

    const result = await pool.query(
      `INSERT INTO user_settings (
        id, user_id, theme, language, currency, date_format, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id) DO UPDATE
      SET theme = COALESCE($3, user_settings.theme),
          language = COALESCE($4, user_settings.language),
          currency = COALESCE($5, user_settings.currency),
          date_format = COALESCE($6, user_settings.date_format),
          updated_at = CURRENT_TIMESTAMP
      RETURNING *`,
      [
        crypto.randomUUID(), req.user.userId,
        theme || 'System', language || 'English', currency || 'INR', date_format || 'DD/MM/YYYY'
      ]
    );

    return res.json({ success: true, message: 'Appearance preferences saved.', settings: result.rows[0] });
  } catch (error) {
    console.error('Update appearance error:', error);
    return res.status(500).json({ success: false, message: 'Could not save appearance preferences.' });
  }
});

// Update security settings
app.put('/api/settings/security', authenticateUser, async (req, res) => {
  try {
    const { biometric_enabled, two_factor_enabled, recovery_email, recovery_mobile } = req.body;

    const result = await pool.query(
      `INSERT INTO security_settings (
        id, user_id, biometric_enabled, two_factor_enabled, recovery_email, recovery_mobile, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id) DO UPDATE
      SET biometric_enabled = COALESCE($3, security_settings.biometric_enabled),
          two_factor_enabled = COALESCE($4, security_settings.two_factor_enabled),
          recovery_email = COALESCE($5, security_settings.recovery_email),
          recovery_mobile = COALESCE($6, security_settings.recovery_mobile),
          updated_at = CURRENT_TIMESTAMP
      RETURNING biometric_enabled, two_factor_enabled, recovery_email, recovery_mobile, updated_at`,
      [
        crypto.randomUUID(), req.user.userId,
        biometric_enabled ?? false, two_factor_enabled ?? false,
        recovery_email ? recovery_email.trim() : null,
        recovery_mobile ? recovery_mobile.trim() : null
      ]
    );

    return res.json({ success: true, message: 'Security preferences saved.', settings: result.rows[0] });
  } catch (error) {
    console.error('Update security settings error:', error);
    return res.status(500).json({ success: false, message: 'Could not save security preferences.' });
  }
});

// --------------------------------------------------
// AI CHATBOT API
// --------------------------------------------------

app.post('/api/chatbot/message', authenticateUser, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ success: false, message: 'Message text is required.' });
    }

    const response = await getChatbotResponse({
      pool,
      userId: req.user.userId,
      message: message.trim(),
    });

    return res.json(response);
  } catch (error) {
    console.error('Chatbot API error:', error);
    return res.status(500).json({
      success: false,
      message: 'Finance assistant is temporarily unavailable. Please try again.',
    });
  }
});

// --------------------------------------------------
// ADMIN OVERVIEW API
// --------------------------------------------------

app.get('/api/admin/overview', authenticateAdmin, async (req, res) => {
  try {
    const [users, expenses, incomes, recentUsers, budgets] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS total FROM users'),
      pool.query(`
        SELECT COUNT(*)::int AS total_transactions, COALESCE(SUM(amount), 0) AS total_amount
        FROM expenses
      `),
      pool.query(`
        SELECT COUNT(*)::int AS total_transactions, COALESCE(SUM(amount), 0) AS total_amount
        FROM incomes
      `),
      pool.query(`
        SELECT id, name, email, mobile, is_active, created_at
        FROM users
        ORDER BY created_at DESC NULLS LAST
        LIMIT 6
      `),
      pool.query('SELECT COUNT(*)::int AS total FROM budgets'),
    ]);

    const totalExpenses = Number(expenses.rows[0].total_amount);
    const totalIncome = Number(incomes.rows[0].total_amount);

    return res.json({
      success: true,
      overview: {
        totalUsers: users.rows[0].total,
        totalExpenses,
        totalIncome,
        totalIncomes: totalIncome,
        totalBudgets: budgets.rows[0].total,
        expenseTransactions: expenses.rows[0].total_transactions,
        incomeTransactions: incomes.rows[0].total_transactions,
        recentUsers: recentUsers.rows,
      },
    });
  } catch (error) {
    console.error('Admin overview error:', error);
    return res.status(500).json({ success: false, message: 'Could not load admin dashboard.' });
  }
});

// --------------------------------------------------
// ADMIN USERS (ACCURATE FINANCIALS, NO DISTINCT BUG)
// --------------------------------------------------

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, 
        u.name, 
        u.email, 
        u.mobile,
        u.email_verified, 
        u.mobile_verified, 
        u.is_active,
        u.created_at,
        COALESCE((SELECT SUM(amount) FROM expenses WHERE user_id = u.id), 0) AS total_expenses,
        COALESCE((SELECT SUM(amount) FROM incomes WHERE user_id = u.id), 0) AS total_incomes,
        (a.user_id IS NOT NULL) AS is_admin
      FROM users u
      LEFT JOIN admin_access a ON u.id = a.user_id
      ORDER BY u.created_at DESC NULLS LAST
      LIMIT 100
    `);

    return res.json({
      success: true,
      users: result.rows.map(row => ({
        ...row,
        total_expenses: Number(row.total_expenses),
        total_incomes: Number(row.total_incomes),
      })),
    });
  } catch (error) {
    console.error('Admin users analytics error:', error);
    return res.status(500).json({ success: false, message: 'Could not load users.' });
  }
});

// Admin toggle user active status
app.put('/api/admin/users/:userId/status', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { is_active } = req.body;

    if (typeof is_active !== 'boolean') {
      return res.status(400).json({ success: false, message: 'is_active boolean is required.' });
    }

    // Safety: Protect last active administrator from being deactivated
    const targetIsAdmin = await pool.query('SELECT user_id FROM admin_access WHERE user_id = $1', [userId]);
    if (targetIsAdmin.rows.length > 0 && !is_active) {
      const activeAdminCount = await pool.query(`
        SELECT COUNT(*)::int AS count 
        FROM admin_access a 
        JOIN users u ON a.user_id = u.id 
        WHERE u.is_active = true
      `);
      if (activeAdminCount.rows[0].count <= 1) {
        return res.status(400).json({
          success: false,
          message: 'Cannot deactivate the last active administrator.',
        });
      }
    }

    const result = await pool.query(
      'UPDATE users SET is_active = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id, name, email, is_active',
      [is_active, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.json({
      success: true,
      message: `User ${is_active ? 'activated' : 'deactivated'} successfully.`,
      user: result.rows[0],
    });
  } catch (error) {
    console.error('Admin user status update error:', error);
    return res.status(500).json({ success: false, message: 'Could not update user status.' });
  }
});

// Admin toggle user role (admin_access)
app.put('/api/admin/users/:userId/role', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { is_admin } = req.body;

    if (typeof is_admin !== 'boolean') {
      return res.status(400).json({ success: false, message: 'is_admin boolean is required.' });
    }

    if (!is_admin) {
      // Check if this is the last admin
      const adminCount = await pool.query('SELECT COUNT(*)::int AS count FROM admin_access');
      if (adminCount.rows[0].count <= 1) {
        return res.status(400).json({
          success: false,
          message: 'Cannot revoke permissions from the only administrator.',
        });
      }
      await pool.query('DELETE FROM admin_access WHERE user_id = $1', [userId]);
    } else {
      await pool.query(
        'INSERT INTO admin_access (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING',
        [userId]
      );
    }

    return res.json({
      success: true,
      message: `User admin role ${is_admin ? 'granted' : 'revoked'} successfully.`,
      is_admin,
    });
  } catch (error) {
    console.error('Admin role update error:', error);
    return res.status(500).json({ success: false, message: 'Could not update user role.' });
  }
});

// --------------------------------------------------
// ADMIN MONTHLY ANALYTICS API
// --------------------------------------------------

app.get('/api/admin/monthly-analytics', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      WITH months AS (
        SELECT generate_series(
          date_trunc('month', CURRENT_DATE) - INTERVAL '5 months',
          date_trunc('month', CURRENT_DATE),
          INTERVAL '1 month'
        )::date AS month
      ),
      monthly_income AS (
        SELECT
          date_trunc('month', income_date)::date AS month,
          SUM(amount) AS total
        FROM incomes
        WHERE income_date >= date_trunc('month', CURRENT_DATE) - INTERVAL '5 months'
        GROUP BY 1
      ),
      monthly_expenses AS (
        SELECT
          date_trunc('month', expense_date)::date AS month,
          SUM(amount) AS total
        FROM expenses
        WHERE expense_date >= date_trunc('month', CURRENT_DATE) - INTERVAL '5 months'
        GROUP BY 1
      )
      SELECT
        to_char(m.month, 'Mon YYYY') AS month,
        COALESCE(i.total, 0) AS income,
        COALESCE(e.total, 0) AS expenses
      FROM months m
      LEFT JOIN monthly_income i ON i.month = m.month
      LEFT JOIN monthly_expenses e ON e.month = m.month
      ORDER BY m.month
    `);

    return res.json({
      success: true,
      analytics: result.rows.map((row) => ({
        month: row.month,
        income: Number(row.income),
        expenses: Number(row.expenses),
      })),
    });
  } catch (error) {
    console.error('Monthly analytics error:', error);
    return res.status(500).json({ success: false, message: 'Could not load monthly analytics.' });
  }
});

// Admin: Get specific user's expenses and incomes
app.get('/api/admin/users/:userId/financials', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const userQuery = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [userId]);
    if (userQuery.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const expensesQuery = await pool.query(
      'SELECT id, amount, category, expense_date, note, created_at FROM expenses WHERE user_id = $1 ORDER BY expense_date DESC',
      [userId]
    );

    const incomesQuery = await pool.query(
      'SELECT id, amount, category, income_date, note, created_at FROM incomes WHERE user_id = $1 ORDER BY income_date DESC',
      [userId]
    );

    return res.json({
      success: true,
      user: userQuery.rows[0],
      expenses: expensesQuery.rows,
      incomes: incomesQuery.rows,
    });
  } catch (error) {
    console.error('Admin user financials error:', error);
    return res.status(500).json({ success: false, message: 'Could not load user financials.' });
  }
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

const PORT = Number(process.env.PORT) || 5000;

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`FinanceFlow backend running on port ${PORT}`);
  console.log(`Server address: http://0.0.0.0:${PORT}`);
});

server.on('error', (error) => {
  console.error('SERVER ERROR:', error);
});

server.on('close', () => {
  console.log('HTTP server has been closed.');
});
