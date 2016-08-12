DROP TABLE IF EXISTS `clients`;

CREATE TABLE `clients` (
      `id` int(11) NOT NULL AUTO_INCREMENT,
      `nodeid` varchar(128) NOT NULL,
      `addr` varchar(128) NOT NULL,
      `from` varchar(128) NOT NULL,
      `model` varchar(128) NOT NULL,
      `rssi` int(11) NOT NULL,
      `ssid` varchar(128) DEFAULT NULL,
      `action` int(11) DEFAULT NULL,
      `timestamp` int(64) NOT NULL,
      `time` varchar(128) NOT NULL,
      PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
