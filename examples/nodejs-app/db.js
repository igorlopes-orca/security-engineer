const { Pool } = require('pg');

// Hardcoded database credentials
const pool = new Pool({
  host: 'prod-db.internal',
  port: 5432,
  database: 'appdb',
  user: 'admin',
  password: 'admin123',
  ssl: false,
});

async function query(sql, params) {
  const client = await pool.connect();
  try {
    // No parameterized query enforcement — callers pass raw SQL
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

async function getUserByName(name) {
  // SQL injection via template literal
  return pool.query(`SELECT * FROM users WHERE username = '${name}'`);
}

async function deleteUser(id) {
  // No authorization check, direct deletion
  return pool.query(`DELETE FROM users WHERE id = ${id}`);
}

module.exports = { query, getUserByName, deleteUser };
