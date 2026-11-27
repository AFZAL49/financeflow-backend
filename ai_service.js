/**
 * AI Finance Assistant Service for FinanceFlow
 * Supports Google Gemini API, OpenAI API, and an intelligent local finance engine
 * that uses real PostgreSQL user financial context.
 */

async function getChatbotResponse({ pool, userId, message }) {
  const userText = (message || '').trim();
  if (!userText) {
    return {
      success: false,
      reply: 'Please ask a financial or app-related question.',
    };
  }

  // 1. Gather privacy-preserving financial facts for this user
  const [expenseStats, incomeStats, topCategories, budgets, goals, loans] = await Promise.all([
    // Current month expenses
    pool.query(`
      SELECT 
        COUNT(*)::int AS count,
        COALESCE(SUM(amount), 0)::numeric AS total
      FROM expenses
      WHERE user_id = $1 
        AND date_trunc('month', expense_date) = date_trunc('month', CURRENT_DATE)
    `, [userId]),

    // Current month income
    pool.query(`
      SELECT 
        COUNT(*)::int AS count,
        COALESCE(SUM(amount), 0)::numeric AS total
      FROM incomes
      WHERE user_id = $1 
        AND date_trunc('month', income_date) = date_trunc('month', CURRENT_DATE)
    `, [userId]),

    // Top expense categories this month
    pool.query(`
      SELECT category, SUM(amount)::numeric AS total, COUNT(*)::int AS count
      FROM expenses
      WHERE user_id = $1 
        AND date_trunc('month', expense_date) = date_trunc('month', CURRENT_DATE)
      GROUP BY category
      ORDER BY total DESC
      LIMIT 3
    `, [userId]),

    // Active budgets
    pool.query(`
      SELECT category, amount::numeric AS limit
      FROM budgets
      WHERE user_id = $1
      ORDER BY created_at DESC
    `, [userId]),

    // Savings goals
    pool.query(`
      SELECT name, target_amount::numeric AS target, saved_amount::numeric AS saved
      FROM savings_goals
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 5
    `, [userId]),

    // Loans
    pool.query(`
      SELECT name, loan_amount::numeric AS total, monthly_emi::numeric AS emi, 
             tenure_months AS tenure, paid_months AS paid
      FROM loans
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 5
    `, [userId]),
  ]);

  const currentMonthExpense = Number(expenseStats.rows[0]?.total || 0);
  const currentMonthIncome = Number(incomeStats.rows[0]?.total || 0);
  const currentMonthBalance = currentMonthIncome - currentMonthExpense;
  const topCategoryList = topCategories.rows.map(r => `${r.category}: ₹${Number(r.total).toFixed(2)} (${r.count} items)`).join(', ') || 'No expenses recorded this month.';
  
  const budgetsList = budgets.rows.map(b => `${b.category}: Limit ₹${Number(b.limit).toFixed(2)}`).join('; ') || 'No budgets configured.';
  const goalsList = goals.rows.map(g => `${g.name}: Saved ₹${Number(g.saved).toFixed(2)} of ₹${Number(g.target).toFixed(2)} (${Math.round((Number(g.saved)/Math.max(1, Number(g.target))) * 100)}%)`).join('; ') || 'No active savings goals.';
  const loansList = loans.rows.map(l => `${l.name}: EMI ₹${Number(l.emi).toFixed(2)}, Paid ${l.paid}/${l.tenure} months`).join('; ') || 'No active loans.';

  const financialContext = {
    currentMonthIncome: `₹${currentMonthIncome.toFixed(2)}`,
    currentMonthExpense: `₹${currentMonthExpense.toFixed(2)}`,
    currentMonthBalance: `₹${currentMonthBalance.toFixed(2)}`,
    topCategories: topCategoryList,
    budgets: budgetsList,
    savingsGoals: goalsList,
    loans: loansList,
  };

  // 2. Try Gemini API if GEMINI_API_KEY is available
  const geminiKey = process.env.GEMINI_API_KEY;
  if (geminiKey && geminiKey.trim()) {
    try {
      const prompt = `You are FinanceFlow AI, a helpful, polite personal finance assistant embedded in the FinanceFlow application.
User Financial Snapshot for Current Month:
- Total Income: ${financialContext.currentMonthIncome}
- Total Expenses: ${financialContext.currentMonthExpense}
- Current Month Balance: ${financialContext.currentMonthBalance}
- Top Spending Categories: ${financialContext.topCategories}
- Budgets: ${financialContext.budgets}
- Savings Goals: ${financialContext.savingsGoals}
- Loans: ${financialContext.loans}

Rules:
1. Provide concise, clear, and actionable answers.
2. Use the user's real numbers when asked about their spending, income, budget, goals, or loans.
3. If asked how to use the app (e.g. add expense, set budget, export report), explain the steps clearly.
4. Disclaimer: You are an educational budgeting assistant, not a licensed financial advisor.
5. Keep response friendly and under 150 words unless detailed explanation is explicitly requested.

User question: "${userText}"`;

      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${geminiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { maxOutputTokens: 300, temperature: 0.3 }
        }),
        signal: AbortSignal.timeout(10000),
      });

      if (response.ok) {
        const data = await response.json();
        const reply = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (reply) {
          return {
            success: true,
            source: 'gemini',
            reply: reply.trim(),
            context: financialContext,
          };
        }
      }
    } catch (apiError) {
      console.warn('Gemini API call failed, falling back to local finance engine:', apiError.message);
    }
  }

  // 3. Try OpenAI API if OPENAI_API_KEY is available
  const openAiKey = process.env.OPENAI_API_KEY;
  if (openAiKey && openAiKey.trim()) {
    try {
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openAiKey}`,
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [
            {
              role: 'system',
              content: `You are FinanceFlow AI, a personal finance assistant. User financial facts: Income: ${financialContext.currentMonthIncome}, Expenses: ${financialContext.currentMonthExpense}, Balance: ${financialContext.currentMonthBalance}, Top Categories: ${financialContext.topCategories}, Budgets: ${financialContext.budgets}, Goals: ${financialContext.savingsGoals}, Loans: ${financialContext.loans}. Keep answers concise, factual, and helpful. Note: Not a licensed financial advisor.`,
            },
            { role: 'user', content: userText },
          ],
          max_tokens: 250,
          temperature: 0.3,
        }),
        signal: AbortSignal.timeout(10000),
      });

      if (response.ok) {
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content;
        if (reply) {
          return {
            success: true,
            source: 'openai',
            reply: reply.trim(),
            context: financialContext,
          };
        }
      }
    } catch (apiError) {
      console.warn('OpenAI API call failed, falling back to local finance engine:', apiError.message);
    }
  }

  // 4. Intelligent Local Finance Engine (Accurate, fast, context-aware rule-based fallback)
  const lower = userText.toLowerCase();

  let reply = '';

  if (lower.includes('how to add') || lower.includes('how do i add') || lower.includes('how to create') || lower.includes('how do i create') || lower.includes('how to set')) {
    if (lower.includes('expense')) {
      reply = `➕ **How to add an expense**:\n1. Tap the **+ Add Expense** button on the Dashboard.\n2. Enter the amount spent.\n3. Choose a category (Food, Shopping, Bills, etc.).\n4. Select the date and add an optional note.\n5. Tap **Save Expense**. It will instantly update your dashboard and PostgreSQL database.`;
    } else if (lower.includes('income')) {
      reply = `➕ **How to add income**:\n1. Tap **Add Income** on the Dashboard.\n2. Enter the received amount.\n3. Select an income category (Salary, Freelance, Business, etc.).\n4. Select the date and optional note.\n5. Tap **Save Income**.`;
    } else if (lower.includes('budget')) {
      reply = `➕ **How to set a budget**:\n1. Tap **Monthly Budget** on your Dashboard.\n2. Enter the spending limit amount.\n3. Select **Overall Budget** or a specific category.\n4. Tap **Set Budget**.`;
    } else if (lower.includes('goal')) {
      reply = `➕ **How to create a savings goal**:\n1. Tap **Savings Goals** on your Dashboard.\n2. Enter the goal title, target amount, and target date.\n3. Tap **Create Goal**.\n4. You can make deposits toward the goal anytime!`;
    } else {
      reply = `📌 In FinanceFlow you can add expenses, income, budgets, savings goals, and loans directly from the Dashboard quick actions or navigation tabs.`;
    }
  } else if (lower.includes('spent') || lower.includes('expense') || lower.includes('spending')) {
    if (lower.includes('highest') || lower.includes('most') || lower.includes('top category') || lower.includes('category')) {
      reply = `📊 **Top Spending Categories this month**:\n${financialContext.topCategories}\n\nTotal expenses so far: **${financialContext.currentMonthExpense}**. Consider setting category budgets to keep spending within desired limits.`;
    } else {
      reply = `💸 **Monthly Spending Overview**:\nYou have recorded **${expenseStats.rows[0]?.count || 0} expenses** totaling **${financialContext.currentMonthExpense}** this month.\n\nTop categories: ${financialContext.topCategories}`;
    }
  } else if (lower.includes('income') || lower.includes('earned') || lower.includes('earning')) {
    reply = `💰 **Monthly Income Overview**:\nYou have recorded **${incomeStats.rows[0]?.count || 0} income transactions** totaling **${financialContext.currentMonthIncome}** this month.`;
  } else if (lower.includes('balance') || lower.includes('net') || lower.includes('saving')) {
    reply = `📈 **Monthly Net Balance**:\n- Income: ${financialContext.currentMonthIncome}\n- Expenses: ${financialContext.currentMonthExpense}\n- **Net Savings**: ${financialContext.currentMonthBalance}\n\n${currentMonthBalance >= 0 ? 'Great job living within your means! You can allocate surplus to your savings goals.' : '⚠️ Your monthly expenses currently exceed income. Look into lowering top discretionary categories.'}`;
  } else if (lower.includes('budget')) {
    if (budgets.rows.length === 0) {
      reply = `🎯 You haven't set any budgets yet. You can create an Overall Budget or Category Budgets (Food, Shopping, Transport, etc.) by tapping **Budget** on your dashboard or quick actions.`;
    } else {
      reply = `🎯 **Your Budgets**:\n${financialContext.budgets}\n\nMonthly expense to date: ${financialContext.currentMonthExpense}. You will receive alerts when spending approaches 80% or exceeds budget.`;
    }
  } else if (lower.includes('goal') || lower.includes('save') || lower.includes('savings')) {
    if (goals.rows.length === 0) {
      reply = `🏆 You don't have active savings goals yet. Tap **Savings Goals** on your dashboard to set a target (e.g., Emergency Fund, Vacation, Gadget) and track regular contributions.`;
    } else {
      reply = `🏆 **Active Savings Goals**:\n${financialContext.savingsGoals}\n\nTip: Consistent small contributions add up quickly!`;
    }
  } else if (lower.includes('loan') || lower.includes('emi') || lower.includes('debt')) {
    if (loans.rows.length === 0) {
      reply = `🏦 You currently have no loans tracked in FinanceFlow. You can add personal loans, auto loans, or home loans in **Loans & EMI** to keep track of tenure and monthly installments.`;
    } else {
      reply = `🏦 **Your Tracked Loans**:\n${financialContext.loans}\n\nRemember to mark each installment as paid to keep your repayment progress accurate!`;
    }
  } else if (lower.includes('profile') || lower.includes('update profile') || lower.includes('change password')) {
    reply = `👤 **Profile & Security**:\nGo to the **Profile** tab at the bottom navigation bar. You can edit your name, contact details, currency, address, and occupation, or tap **Security** to change your password and manage active sessions.`;
  } else if (lower.includes('hello') || lower.includes('hi') || lower.includes('hey')) {
    reply = `Hello! 👋 I'm your FinanceFlow Assistant. I can help answer questions about your spending, income, budgets, savings goals, loans, or how to use the app. How can I help you today?`;
  } else {
    reply = `💡 I'm here to help with your personal finances. Here is your current snapshot:\n• Income: ${financialContext.currentMonthIncome}\n• Expenses: ${financialContext.currentMonthExpense}\n• Net Balance: ${financialContext.currentMonthBalance}\n\nAsk me questions like *"How much have I spent this month?"*, *"Which category is highest?"*, or *"How do I add a budget?"*`;
  }

  return {
    success: true,
    source: 'local_finance_engine',
    reply,
    context: financialContext,
  };
}

module.exports = {
  getChatbotResponse,
};
