## Возможности:

1. Удаление и добавление шаблонов для nginx проксирования в ISP Manager 6 Lite, Pro, Host как массовое так и по одному
2. Добавление уже предустановленных (в скрипте) шаблонов пользоватей для Nginx + PHP-FPM и CMS Wordpress, Вitrix, Opencart, Moodle, Magento2, Webasyst, CS-Cart
3. Для 1С Битрикс реализована поддержка работы (авто)композита (заголовок X-Bitrix-Composite) Nginx (file), Nginx (memcached), Bitrix Cache (200) в связках nginx+apache и nginx+php-fpm

Принцип работы реализован такой: сначала nginx проверит наличие `$корень_сайта/bitrix/.bxfile_composite_enabled` (заголовок будет X-Bitrix-Composite: Bitrix Cache (200)), если его нет, html файла кэша `$корень_сайта/bitrix/html_pages/$сайт` (X-Bitrix-Composite: Nginx (file)), и затем memcached (X-Bitrix-Composite: Nginx (memcached)), в случае неудачи с memcached пойдёт к ядру Битрикс (при переключении с файлового кеша композита на memcached необходимо обязательно очистить каталог `bitrix/html_pages/*`).

В случае использования X-Bitrix-Composite: Nginx (memcached) наиболее производительное решение, но бекенду 1С-Битрикс будут недоступны клиентские заголовки, можно дописать серверные заголовки на стороне nginx.

В случае использования X-Bitrix-Composite: Nginx (file) решение менее производительное, но всё равно быстрое, бекенду 1С-Битрикс также недоступны клиентские заголовки, можно дописать серверные заголовки на стороне nginx.

В случае использования X-Bitrix-Composite: Bitrix Cache (200) наименее быстрое (php отдаёт html файл композита), но при этом все заголовки бекенда 1С-Битрикс в том числе клиентские доступны, также можно дописать серверные заголовки и на стороне nginx.

Автокомпозит c [Ammina opimizer](http://marketplace.1c-bitrix.ru/solutions/ammina.optimizer/ "Ammina opimizer") для Битрикс:
- Отмечаем чек-бокс "Авторедирект на корректную страницу при наличии в строке запроса параметра iswebp" в настройках модуля в админке Битрикс
- Скачиваем https://www.ammina.ru/upload/sysfiles/ammina_composite.conf в /etc/nginx/vhosts-resources/ваш_сайт/
- Заменяем `${root_path}` в скачанном файле на путь до корня сайта
- Перезапускаем nginx:
```
nginx -t && nginx -s reload
```

5. Резервное копирование /etc и текущих шаблонов с автоматическим восстановлением если вдруг что-то пошло не так
6. Оптимизация основных параметров для PHP и MySQL средствами API панели управления после установки спец. шаблонов (wordpress, bitrix и др.). Список изменяемых параметров выводится при работе скрипта.

```
bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) tweak
```

7. Сброс всех шаблонов панели (возврат на настройки по умолчанию для панели управления)
8. Пересборка на debian/rhel nginx с требуемыми модулями (brotli, push server, headers more и тд) и последними версиями openssl, libressl, boringssl

```
bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) recompile
```

Для шаблона с bitrix автоматическая детекция и пересборка после положительного ответа скрипту

## Запуск:
1. Напрямую из репозитория:
```
bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi)
```
2. Скачать локально и запустить:
```
cd /tmp 
wget --no-check-certificate "https://raw.githubusercontent.com/attaattaatta/proxy_preset_builder/master/proxy_preset_builder.sh"
bash proxy_preset_builder.sh
```
3. Сброс и удаление всех внесённых изменений если что-то пошло не так:
```
bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) reset
```
## Использование:

* Для просмотра всех параметров и примеров запустите скрипт без параметров
* После добавления любого шаблона с помощью этого скрипта создайте пользователя в панели управления и примените этот шаблон для него
* Затем создайте сайт и выберите владельцем созданного пользователя либо если пользователь уже существует и сайт уже создан, примените этот шаблон к сущестувющему пользователю и сайту нажав OK в редактировании сайта

## Пример запуска без параметров:
```
bash /tmp/proxy_preset_builder.sh


Hello, my version is 1.0.8

ISP Manager version checking
ISP Manager version (6.70.1) suits
ISP Manager release (ISPmanager Lite) suits

Listing existing templates:
---------------
proxy_to_wordpress_fpm
proxy_to_bitrix_fpm
proxy_to_opencart_fpm
proxy_to_moodle_fpm
proxy_to_webassyst_fpm
proxy_to_magento2_fpm
proxy_to_127.0.0.1:3000
proxy_to_unix:/home/atta/myapp/guni.sock:
---------------

Example for 1 preset: /tmp/123 add wordpress_fpm OR /tmp/123 add 127.0.0.1:8088
Example for 4 presets: /tmp/123 add wordpress_fpm 127.0.0.1:8000 1.1.1.1 /path/to/unix/socket

Delete all existing %proxy_to_*% presets and injects: /tmp/123 del all proxy_to_
Delete one existing preset and inject: /tmp/123 del proxy_to_wordpress_fpm OR /tmp/123 del proxy_to_127.0.0.1:8000
Restore default templates and delete all presets: /tmp/123 reset

Tweak some general PHP and MySQL options: /tmp/123 tweak
Recompile nginx (add/remove modules | update/change SSL): /tmp/123 recompile

Current special templates list: wordpress_fpm, bitrix_fpm, opencart_fpm, moodle_fpm, webassyst_fpm, magento2_fpm, cscart_fpm


ERROR - Not enough arguments, please specify proxy target/targets
```
## Пример использования:
Настройка проксирования на 127.0.0.1:5000
```
bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) add 127.0.0.1:5000
```
Настройка проксирования на 1.1.1.1:80 + проксирования на 127.0.0.1:8088
```
bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) add 1.1.1.1:80 127.0.0.1:8088
```
Добавление только шаблона для bitrix
```
bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) add bitrix_fpm
```
Добавление множества шаблонов
```
bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) add bitrix_fpm opencart_fpm wordpress_fpm moodle_fpm magento2_fpm
```
Сброс всех добавленных шаблонов и инъекций и добавление следом проксирования на 127.0.0.1:9000
```
echo y | bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) reset && bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) add 127.0.0.1:9000
```
