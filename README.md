## Возможности:

1. Удаление и добавление шаблонов для nginx проксирования в ISP Manager 6 Lite, Pro, Host как массовое так и по одному
2. Добавление уже предустановленных (в скрипте) шаблонов wordpress, bitrix, opencart (в оновном для связки nginx + php-fpm, но также оставлена совместимость с другими связками)
3. Для 1С Битрикс реализована поддержка работы (авто)композита как Nginx (file), так и Nginx (memcached) в связках nginx+apache и nginx+php-fpm
4. Резервное копирование /etc и текущих шаблонов с автоматическим восстановлением если вдруг что-то пошло не так
5. Оптимизация основных параметров для PHP и MySQL средствами API панели управления после установки спец. шаблонов (wordpress, bitrix и др.). Список изменяемых параметров выводится при работе скрипта.
6. Сброс всех шаблонов панели (возврат на настройки по умолчанию для панели управления)

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
## Использование:

* Для просмотра всех параметров и примеров запустите скрипт без параметров<br />
* После добавления любого шаблона с помощью этого скрипта создайте пользователя в панели управления и примените этот шаблон для него<br />
* Затем создайте www-домен и выберите владельцем созданного пользователя либо если пользователь уже существует и www-домен уже создан примените шаблон к сущестувющему пользователю и сайту нажав OK в редактировании

## Пример запуска без параметров:
```
bash /tmp/proxy_preset_builder.sh

Hello, my version is 1.0.2

ISP Manager version checking
ISP Manager version (6.29.1) suits
ISP Manager release (ISPmanager Lite) suits

Listing existing presets:
---------------
proxy_to_127.0.0.1:5000
proxy_to_bitrix_fpm
proxy_to_opencart_fpm
---------------

Example for 1 preset: /tmp/proxy_preset_builder.sh add wordpress_fpm OR /tmp/proxy_preset_builder.sh add 127.0.0.1:8088
Example for 4 presets: /tmp/proxy_preset_builder.sh add wordpress_fpm 127.0.0.1:8000 1.1.1.1 /path/to/unix/socket

Delete all existing %proxy_to_*% presets and injects: /tmp/proxy_preset_builder.sh del all proxy_to_
Delete one existing preset and inject: /tmp/proxy_preset_builder.sh del proxy_to_wordpress_fpm OR /tmp/proxy_preset_builder.sh del proxy_to_127.0.0.1:8000
Restore default templates and delete all presets: /tmp/proxy_preset_builder.sh reset

Current specials list: wordpress_fpm, bitrix_fpm, opencart_fpm (soon magento_fpm, passenger_ruby, gitlab_fpm)


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
Добавление шаблона для bitrix
```
bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) add bitrix_fpm
```
Сброс всех добавленных шаблонов и инъекций и добавление следом проксирования на 127.0.0.1:9000
```
echo y | bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) reset && bash <(wget --no-check-certificate -q -o /dev/null -O- https://bit.ly/3q9BCQi) add 127.0.0.1:9000
```
