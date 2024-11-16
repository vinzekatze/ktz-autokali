# ktz-autokali

Библиотека [bashmator](https://github.com/vinzekatze/bashmator) для __kali linux__.

Потихоньку коплю тут всякие сомнительные скрипты.

## Установка

Устанавливать bashmator рекомендуется через pipx.

```
# Установка pipx
sudo apt update
sudo apt install pipx
sudo pipx ensurepath --global

# Установка bashmator
sudo pipx install bashmator --global
```

Скачать и добавить библиотеку:

```
git clone https://github.com/vinzekatze/ktz-autokali

# для пользователя
bshm library add ktz-autokali
bshm library use ktz-autokali

# для рута
sudo bshm library add ktz-autokali
sudo bshm library use ktz-autokali
```

Установить все необходимое и добавить оболочки в `bshm`:

```
bshm use install --item 1-8
sudo bshm use install --item 8
```
После установки рекомендуется перелогиниться из-за docker

## Обновление
С недавних пор для совсем ленивых (для меня) присутствует скрипт с git pull, чтобы подгружать новые файлы без перехода в папку:

```
bshm use pull
```
Если модуля нет в вашей версии, зайдите в корневую папку библиотеки и сделайте `git pull` вручную