-- 作业：特征表 + 载荷表（一对多，支持多类型）
-- 在 MySQL 中执行: mysql -u root -p < schema.sql
-- 或先 CREATE DATABASE 再 USE

CREATE DATABASE IF NOT EXISTS packet_capture DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE packet_capture;

DROP TABLE IF EXISTS payload;
DROP TABLE IF EXISTS feature;

CREATE TABLE feature (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '特征序列号',
    src_ip VARCHAR(45) NOT NULL COMMENT '源IP',
    dst_ip VARCHAR(45) NOT NULL COMMENT '目的IP',
    src_port INT UNSIGNED NOT NULL COMMENT '源端口',
    dst_port INT UNSIGNED NOT NULL COMMENT '目的端口',
    content_type VARCHAR(128) NOT NULL COMMENT 'HTTP Content-Type',
    payload_size INT UNSIGNED NOT NULL COMMENT '载荷大小',
    PRIMARY KEY (id),
    KEY idx_flow (src_ip, dst_ip, src_port, dst_port),
    KEY idx_content_type (content_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='特征表';

CREATE TABLE payload (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '载荷表序列号',
    file_path VARCHAR(1024) NOT NULL COMMENT '文件存储路径',
    file_offset BIGINT UNSIGNED NOT NULL COMMENT '载荷在文件中的偏移',
    data_type VARCHAR(64) NOT NULL DEFAULT 'unknown' COMMENT '数据类型(image/txt/html/json/css/js/gzip/unknown)',
    feature_id INT UNSIGNED NOT NULL COMMENT '特征序列号',
    PRIMARY KEY (id),
    KEY idx_feature (feature_id),
    KEY idx_file_offset (file_offset),
    CONSTRAINT fk_payload_feature
        FOREIGN KEY (feature_id) REFERENCES feature(id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='载荷表';