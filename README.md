# Port Monitor

Локальный сервис мониторинга открытых портов на серверах через nmap.

## Стек

| Компонент | Технология | Обоснование |
|-----------|-----------|-------------|
| Backend | Python 3.12 + FastAPI | Простой API, авто-документация `/api/docs`, минимум бойлерплейта |
| ORM | SQLAlchemy 2 (sync) | nmap — синхронный, async не нужен; проще дебажить |
| База данных | PostgreSQL 16 | Надёжное хранение истории сканов, индексы, агрегации |
| Сканер | python-nmap | Обёртка над системным nmap; поддержка TCP + UDP |
| Фоновые задачи | FastAPI BackgroundTasks | Встроено в FastAPI, без Redis/Celery |
| Frontend | Bootstrap 5 + Vanilla JS | Один HTML-файл, нет сборки, легко менять |
| Контейнеры | Docker Compose | Воспроизводимая DEV-среда, одна команда запуска |

**Redis не нужен** — фоновые задачи обрабатываются BackgroundTasks (in-process), достаточно для локального использования.

## Быстрый старт (DEV)

```bash
# 1. Перейти в директорию проекта
cd port_monitoring

# 2. Запустить
docker compose up --build

# 3. Открыть UI
open http://localhost:8000

# 4. Swagger-документация API
open http://localhost:8000/api/docs
```

## Аутентификация

Один admin-пользователь, настраивается через переменные окружения (нет таблицы
пользователей). Авторизация включена по умолчанию — API защищён JWT-токеном,
в UI открывается страница входа.

```bash
# 1. Создать .env из примера
cp .env.example .env

# 2. Задать пароль и секрет для подписи токенов
#    JWT_SECRET можно сгенерировать так:
openssl rand -hex 32
```

Переменные окружения (см. `.env.example`):

| Переменная           | По умолчанию | Назначение                                        |
|----------------------|--------------|---------------------------------------------------|
| `AUTH_ENABLED`       | `true`       | `false` — полностью отключить авторизацию          |
| `ADMIN_USERNAME`     | `admin`      | Имя пользователя                                  |
| `ADMIN_PASSWORD`     | —            | Пароль (обязателен, если auth включён)            |
| `JWT_SECRET`         | —            | Секрет подписи JWT (обязателен, если auth включён)|
| `JWT_EXPIRE_MINUTES` | `720`        | Время жизни токена в минутах (12ч)                |

Если `AUTH_ENABLED=true`, но `ADMIN_PASSWORD`/`JWT_SECRET` не заданы, вход
невозможен (логин всегда отклоняется). Токен хранится в `localStorage` и
передаётся в заголовке `Authorization: Bearer <token>`. Публичны только
`/health`, статика SPA и эндпоинты `/api/auth/login` и `/api/auth/config`.

## Структура проекта

```
port_monitoring/
├── app/
│   ├── main.py        # FastAPI приложение, роуты
│   ├── models.py      # SQLAlchemy ORM модели
│   ├── schemas.py     # Pydantic схемы (валидация, сериализация)
│   ├── crud.py        # Операции с базой данных
│   ├── scanner.py     # Запуск nmap, парсинг результатов
│   └── database.py    # Подключение к БД, сессии
├── frontend/
│   └── index.html     # SPA (один файл, без сборки)
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

## База данных

### Схема

**`targets`** — серверы для мониторинга

| Колонка | Тип | Описание |
|---------|-----|----------|
| id | serial PK | |
| name | varchar | Человекочитаемое имя |
| host | varchar UNIQUE | IP-адрес или hostname |
| description | text | Опциональное описание |
| is_active | bool | Мягкое удаление |
| created_at | timestamp | Дата добавления |

**`scans`** — история сканирований

| Колонка | Тип | Описание |
|---------|-----|----------|
| id | serial PK | |
| target_id | FK → targets | |
| started_at | timestamp | |
| finished_at | timestamp | NULL пока идёт скан |
| status | varchar | `pending` → `running` → `completed` / `failed` |
| scan_type | varchar | `tcp`, `udp`, `both` |
| open_ports_count | int | Кэшированное число открытых портов |
| error_message | text | Текст ошибки при сбое |

**`open_ports`** — найденные порты

| Колонка | Тип | Описание |
|---------|-----|----------|
| id | serial PK | |
| scan_id | FK → scans | |
| port | int | Номер порта |
| protocol | varchar | `tcp` / `udp` |
| state | varchar | `open`, `open\|filtered` |
| service | varchar | Имя сервиса (ssh, http...) |
| product | varchar | Название ПО (OpenSSH, nginx...) |
| version | varchar | Версия |
| extra_info | text | Дополнительная информация nmap |

## API

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/targets` | Список целей с последними данными |
| POST | `/api/targets` | Добавить цель |
| DELETE | `/api/targets/{id}` | Удалить цель (soft delete) |
| POST | `/api/targets/{id}/scan` | Запустить сканирование |
| GET | `/api/scans` | История сканов (`?target_id=` для фильтра) |
| GET | `/api/scans/{id}` | Детали скана с портами |
| GET | `/api/stats` | Сводная статистика |

Полная интерактивная документация: `http://localhost:8000/api/docs`

## Типы сканирований

| Тип | nmap-аргументы | Требования |
|-----|---------------|-----------|
| TCP | `-sV --open -T4` | Нет (user-space) |
| UDP | `-sU --top-ports 100 --open -T4` | root / `cap_net_raw` |
| Both | TCP + UDP | root для UDP |

В Docker Compose уже выставлены `cap_add: [NET_RAW, NET_ADMIN]` для UDP-сканов.

При запуске без Docker для UDP: `sudo uvicorn app.main:app ...`

## Обновление зависимостей

```bash
pip install -r requirements.txt
# Схема БД создаётся автоматически при старте (SQLAlchemy create_all).
# Для продакшн-миграций добавить Alembic: pip install alembic
```
