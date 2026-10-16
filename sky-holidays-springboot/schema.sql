CREATE DATABASE IF NOT EXISTS sky_holidays CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE sky_holidays;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(80) NOT NULL,
  email VARCHAR(120) NOT NULL UNIQUE,
  pass_hash VARCHAR(100) NOT NULL,
  role ENUM('admin','client') NOT NULL DEFAULT 'client',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- buses, rooms, food/hotel and places all live in one table, separated by `kind`
CREATE TABLE IF NOT EXISTS items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  kind ENUM('bus','room','food','place') NOT NULL,
  name VARCHAR(120) NOT NULL,
  type VARCHAR(60) DEFAULT NULL,
  loc VARCHAR(120) DEFAULT NULL,
  seats INT DEFAULT NULL,
  price DECIMAL(10,2) NOT NULL DEFAULT 0,
  status ENUM('Available','Unavailable') NOT NULL DEFAULT 'Available',
  img VARCHAR(200) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX (kind)
);

CREATE TABLE IF NOT EXISTS bookings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  item_id INT NULL,
  item_name VARCHAR(120) NOT NULL,
  qty INT NOT NULL DEFAULT 1,
  days INT NOT NULL DEFAULT 1,
  travel_date DATE NOT NULL,
  amount DECIMAL(10,2) NOT NULL DEFAULT 0,
  pay_method VARCHAR(20) NOT NULL DEFAULT 'Cash',
  pay_status VARCHAR(30) NOT NULL DEFAULT 'Unpaid',
  pay_ref VARCHAR(40) DEFAULT NULL,
  status ENUM('Pending','Confirmed','Cancelled') NOT NULL DEFAULT 'Pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS enquiries (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(80) NOT NULL,
  mobile VARCHAR(20) DEFAULT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
