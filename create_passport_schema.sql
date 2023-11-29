CREATE TABLE `accounts` (
  `id` bigint NOT NULL,
  `email` varchar(50) COLLATE utf8mb3_bin DEFAULT NULL,
  `email_verified` tinyint DEFAULT NULL,
  `picture` varchar(200) COLLATE utf8mb3_bin DEFAULT NULL,
  `display_name` varchar(50) COLLATE utf8mb3_bin DEFAULT NULL,
  `username` varchar(50) COLLATE utf8mb3_bin DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;

CREATE TABLE `sessions` (
  `id` varchar(20) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `user_id` bigint NOT NULL,
  `created` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;

CREATE TABLE `oauth` (
  `provider` varchar(50) COLLATE utf8mb3_bin NOT NULL,
  `sub` varchar(50) COLLATE utf8mb3_bin NOT NULL,
  `user_id` bigint NOT NULL,
  `token` text COLLATE utf8mb3_bin,
  PRIMARY KEY (`provider`,`sub`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
