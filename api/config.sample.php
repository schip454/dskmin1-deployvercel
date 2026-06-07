<?php
/**
 * config.sample.php — ШАБЛОН конфигурации обработчика заявок.
 *
 * НА СЕРВЕРЕ:
 *   1) Скопируй этот файл в config.php  (cp config.sample.php config.php)
 *   2) Впиши реальные значения вместо «ЗАПОЛНИ_…»
 *   3) config.php НЕ кладётся в git/архив и закрыт от веба через .htaccess
 *
 * Секреты (токены/пароли) живут ТОЛЬКО здесь, на сервере. В код сайта не попадают.
 */

return [

    // Откуда разрешаем POST с формы (CORS). Прод — same-origin, превью Vercel — кросс-домен.
    'cors_origins' => [
        'https://dskmin1.ru',
        'https://www.dskmin1.ru',
        'https://dskmin1.online',
        'https://www.dskmin1.online',
        'https://dskmin1-deployvercel.vercel.app', // превью для заказчика; убери если не нужно
    ],

    // База данных MySQL (создаётся в ISPmanager → Базы данных)
    'db' => [
        'host' => 'localhost',
        'name' => 'ЗАПОЛНИ_имя_базы',
        'user' => 'ЗАПОЛНИ_пользователь',
        'pass' => 'ЗАПОЛНИ_пароль',
    ],

    // Антифлуд: не больше max заявок с одного IP за window секунд
    'rate_limit' => ['max' => 5, 'window' => 60],

    // Спам-фильтр (тихий дроп при совпадении — бот думает что успех)
    'spam_patterns' => [
        '/\b(viagra|cialis|casino|porn|escort|loan|bitcoin|crypto|forex)\b/iu',
        '/(seo[\- ]?продвижени|раскрутк[аи] сайт|вывод в топ|накрутк)/iu',
        '/https?:\/\/\S+\s+https?:\/\/\S+/iu', // 2+ ссылок подряд
        '/[\x{4e00}-\x{9fff}\x{0600}-\x{06ff}]/u', // CJK / арабица в тексте
    ],

    // === КАНАЛ 1: Telegram (работает сразу) ===
    'telegram' => [
        'enabled'  => true,
        'token'    => 'ЗАПОЛНИ_TELEGRAM_BOT_TOKEN', // от @BotFather (перевыпусти, т.к. светился в чате)
        'chat_ids' => ['ЗАПОЛНИ_CHAT_ID'],           // ТВОЙ chat_id (не id бота!). Можно несколько.
    ],

    // === КАНАЛ 2: Max (включить после получения токена) ===
    'max' => [
        'enabled'  => false,
        'token'    => '',
        'chat_ids' => [],
        'api_base' => 'https://botapi.max.ru', // уточним при подключении
    ],

    // === КАНАЛ 3: E-mail (включить после создания ящика на домене или app-пароля mail.ru) ===
    'email' => [
        'enabled'     => false, // ← поставь true когда заполнишь SMTP
        // Вариант А (рекомендуется сейчас): ящик на домене reg.ru
        //   smtp_host см. в reg.ru → Почта (обычно mail.hosting.reg.ru или smtp.reg.ru)
        // Вариант Б (позже): mail.ru — smtp.mail.ru / 465 / ssl / app-пароль
        'smtp_host'   => 'ЗАПОЛНИ_smtp_host',
        'smtp_port'   => 465,
        'smtp_secure' => 'ssl',                 // 'ssl' для 465, 'tls' для 587
        'smtp_user'   => 'ЗАПОЛНИ_логин_ящика', // напр. info@dskmin1.ru
        'smtp_pass'   => 'ЗАПОЛНИ_пароль_ящика',
        'from'        => 'info@dskmin1.ru',
        'from_name'   => 'Сайт ДСК МИН-1',
        'to'          => ['ooo.dskmin1@mail.ru', 'schipanovad@gmail.com'],
    ],
];
