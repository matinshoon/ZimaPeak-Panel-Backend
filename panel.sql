-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: localhost:8889
-- Generation Time: Apr 14, 2024 at 06:39 AM
-- Server version: 5.7.39
-- PHP Version: 7.4.33

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `test`
--

-- --------------------------------------------------------

--
-- Table structure for table `Contacts`
--

CREATE TABLE `Contacts` (
  `id` varchar(255) NOT NULL,
  `Name` varchar(255) NOT NULL,
  `Phone` varchar(20) DEFAULT NULL,
  `Email` varchar(255) DEFAULT NULL,
  `Website` varchar(255) DEFAULT NULL,
  `status` varchar(255) NOT NULL DEFAULT 'active',
  `date_added` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `emails_sent` int(11) DEFAULT '0',
  `Note` varchar(255) DEFAULT 'Click to add Note',
  `added_by` varchar(255) DEFAULT NULL,
  `trash` tinyint(1) DEFAULT '0',
  `deleted_by` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `events`
--

CREATE TABLE `events` (
  `id` varchar(36) NOT NULL,
  `name` varchar(255) NOT NULL,
  `start_date` varchar(255) DEFAULT NULL,
  `end_date` varchar(255) DEFAULT NULL,
  `client_name` varchar(255) NOT NULL,
  `client_email` varchar(255) NOT NULL,
  `priority` int(11) NOT NULL,
  `added_by` char(36) DEFAULT NULL,
  `added_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `sendgrid_events`
--

CREATE TABLE `sendgrid_events` (
  `id` int(11) NOT NULL,
  `email` varchar(255) DEFAULT NULL,
  `timestamp` datetime DEFAULT NULL,
  `event` varchar(50) DEFAULT NULL,
  `sg_event_id` varchar(255) DEFAULT NULL,
  `sg_message_id` varchar(255) DEFAULT NULL,
  `response` varchar(255) DEFAULT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `status` varchar(50) DEFAULT NULL,
  `useragent` varchar(255) DEFAULT NULL,
  `ip` varchar(50) DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  `asm_group_id` int(11) DEFAULT NULL,
  `payload` text,
  `event_type` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `sent_emails`
--

CREATE TABLE `sent_emails` (
  `id` varchar(36) NOT NULL,
  `to_email` text,
  `from_email` varchar(255) NOT NULL,
  `subject` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `footer` text,
  `sent_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `TodoList`
--

CREATE TABLE `TodoList` (
  `id` varchar(36) NOT NULL,
  `name` varchar(255) NOT NULL,
  `completed` tinyint(1) NOT NULL DEFAULT '0',
  `added_by` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` varchar(36) NOT NULL,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `fullname` varchar(255) DEFAULT NULL,
  `role` enum('user','admin') NOT NULL,
  `password` varchar(255) NOT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'offline',
  `state` varchar(50) DEFAULT 'active',
  `income` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `fullname`, `role`, `password`, `status`, `state`, `income`) VALUES
('9d9ac90e-d819-46fe-ae96-b73d21cc8221', 'Alex', 'Alex@zimapeak.com', 'Alex', 'user', '$2b$10$cychI2ZgUm8N/n6wjet9a.1QG6c2PAQtSDghE/mOdvsoqifyQK6.m', 'offline', 'active', NULL),
('c05b43f8-9232-4feb-993a-822d9f3f2cfc', 'Matt', 'Matt@zimapeak.com', 'Matt', 'admin', '$2b$10$cychI2ZgUm8N/n6wjet9a.1QG6c2PAQtSDghE/mOdvsoqifyQK6.m', 'offline', 'active', NULL);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `Contacts`
--
ALTER TABLE `Contacts`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `events`
--
ALTER TABLE `events`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `sendgrid_events`
--
ALTER TABLE `sendgrid_events`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `sent_emails`
--
ALTER TABLE `sent_emails`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `TodoList`
--
ALTER TABLE `TodoList`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `sendgrid_events`
--
ALTER TABLE `sendgrid_events`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

DELIMITER $$
--
-- Events
--
CREATE DEFINER=`root`@`localhost` EVENT `remove_old_data_event` ON SCHEDULE EVERY 1 DAY STARTS '2024-03-25 21:20:00' ON COMPLETION NOT PRESERVE ENABLE DO DELETE FROM sendgrid_events
  WHERE TIMESTAMPDIFF(DAY, timestamp, NOW()) >= 60$$

DELIMITER ;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
