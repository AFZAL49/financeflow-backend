require('dotenv').config();
const fs = require('node:fs');
const path = require('node:path');
const pool = require('./database');

async function runMigration() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));

    // 1. users: ensure is_active exists for admin account management
    await client.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;
    `);

    // 2. savings_goals: add target_date and description
    await client.query(`
      ALTER TABLE savings_goals 
      ADD COLUMN IF NOT EXISTS target_date DATE,
      ADD COLUMN IF NOT EXISTS description TEXT;
    `);

    // 3. loans: add interest_rate, start_date, lender_name, loan_type ('borrowed' | 'lent')
    await client.query(`
      ALTER TABLE loans 
      ADD COLUMN IF NOT EXISTS interest_rate NUMERIC DEFAULT 0,
      ADD COLUMN IF NOT EXISTS start_date DATE DEFAULT CURRENT_DATE,
      ADD COLUMN IF NOT EXISTS lender_name VARCHAR(255),
      ADD COLUMN IF NOT EXISTS loan_type VARCHAR(50) DEFAULT 'borrowed';
    `);

    // 4. Ensure useful indexes exist for performance & isolation
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(user_id, expense_date);
      CREATE INDEX IF NOT EXISTS idx_incomes_user_date ON incomes(user_id, income_date);
      CREATE INDEX IF NOT EXISTS idx_budgets_user_month ON budgets(user_id, budget_month);
      CREATE INDEX IF NOT EXISTS idx_savings_goals_user ON savings_goals(user_id);
      CREATE INDEX IF NOT EXISTS idx_loans_user ON loans(user_id);
    `);

    await client.query('COMMIT');
    console.log('Migration completed successfully!');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Migration failed:', err);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

runMigration().catch(error => {
  console.error('Database setup failed:', error.message);
  process.exitCode = 1;
});
