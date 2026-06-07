-- Схема БД для приёма заявок ДСК МИН-1.
-- Импорт: ISPmanager → Базы данных → phpMyAdmin → выбрать БД → Импорт → этот файл.

CREATE TABLE IF NOT EXISTS leads (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    created_at  DATETIME      NOT NULL,
    ip          VARCHAR(45)   NOT NULL DEFAULT '',
    name        VARCHAR(255)  NOT NULL,
    phone       VARCHAR(64)   NOT NULL,
    comment     TEXT          NULL,
    object      VARCHAR(255)  NULL,
    user_agent  VARCHAR(255)  NULL,
    referer     VARCHAR(255)  NULL,
    INDEX idx_created (created_at),
    INDEX idx_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rate_limit (
    ip          VARCHAR(45)  PRIMARY KEY,
    timestamps  TEXT         NULL,
    updated_at  DATETIME     NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
