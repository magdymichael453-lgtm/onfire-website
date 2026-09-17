const mysql = require('mysql2');
if (process.env.NODE_ENV !== 'production') require('dotenv').config();

const pool = mysql.createPool({
  host:     process.env.DB_HOST     || process.env.MYSQLHOST     || 'localhost',
  user:     process.env.DB_USER     || process.env.MYSQLUSER     || 'root',
  password: process.env.DB_PASSWORD || process.env.MYSQLPASSWORD || '',
  database: process.env.DB_NAME     || process.env.MYSQLDATABASE || 'onfire_db',
  port:     Number(process.env.DB_PORT || process.env.MYSQLPORT || 3306),
  waitForConnections: true,
  connectionLimit: 10,
});

pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ خطأ في الاتصال بـ MySQL:', err.code, '-', err.message);
  } else {
    console.log('✅ تم الاتصال بـ MySQL بنجاح');
    connection.release();
  }
});

module.exports = pool.promise();
