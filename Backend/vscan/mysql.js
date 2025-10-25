const mysql = require("mysql2/promise"); // Use promise-based version for async/await

// Create a connection pool
const pool = mysql.createPool({
  host: "localhost", // Database host
  user: "root", // MySQL username
  password: "4152325dD@", // MySQL password
  database: "vscan", // Database name
  waitForConnections: true, // Wait for connections when pool is full
  connectionLimit: 10, // Maximum number of connections
  queueLimit: 0, // Unlimited queue for pending connections
});

// Export a function to get a connection
module.exports = {
  query: async (sql, params) => {
    const connection = await pool.getConnection();
    try {
      const [results] = await connection.execute(sql, params);
      return results;
    } finally {
      connection.release(); // Always release connection back to the pool
    }
  },
};
