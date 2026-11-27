CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL,
  mobile text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  date_of_birth date,
  gender text,
  country text,
  address text,
  city text,
  state text,
  pin_code text,
  occupation text,
  employment_type text,
  monthly_income numeric,
  preferred_currency text DEFAULT 'INR',
  language text DEFAULT 'English',
  date_format text DEFAULT 'DD/MM/YYYY',
  email_verified boolean DEFAULT false,
  mobile_verified boolean DEFAULT false,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_access (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS login_sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip_address text,
  user_agent text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS expenses (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount numeric NOT NULL,
  category text NOT NULL,
  expense_date date NOT NULL,
  note text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS incomes (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount numeric NOT NULL,
  category text NOT NULL,
  income_date date NOT NULL,
  note text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS budgets (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category text NOT NULL,
  amount numeric NOT NULL,
  budget_month date NOT NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS savings_goals (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  target_amount numeric NOT NULL,
  saved_amount numeric DEFAULT 0,
  target_date date,
  description text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS loans (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  loan_amount numeric NOT NULL,
  monthly_emi numeric NOT NULL,
  tenure_months integer NOT NULL,
  paid_months integer DEFAULT 0,
  interest_rate numeric DEFAULT 0,
  start_date date DEFAULT CURRENT_DATE,
  lender_name text,
  loan_type text DEFAULT 'borrowed',
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notification_settings (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  expense_alerts boolean DEFAULT true,
  income_alerts boolean DEFAULT true,
  budget_alerts boolean DEFAULT true,
  savings_goal_alerts boolean DEFAULT true,
  loan_emi_alerts boolean DEFAULT true,
  security_alerts boolean DEFAULT true,
  promotional_alerts boolean DEFAULT false,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_settings (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  theme text DEFAULT 'System',
  language text DEFAULT 'English',
  currency text DEFAULT 'INR',
  date_format text DEFAULT 'DD/MM/YYYY',
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS security_settings (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  biometric_enabled boolean DEFAULT false,
  two_factor_enabled boolean DEFAULT false,
  recovery_email text,
  recovery_mobile text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS financeflow_users_email_lower ON users (lower(email));
