# ktz-autokali

Библиотека [bashmator](https://github.com/vinzekatze/bashmator) для __kali linux__.

Потихоньку коплю тут всякие сомнительные скрипты.

## Установка

Скачать и добавить библиотеку:

```
git clone https://github.com/vinzekatze/ktz-autokali
bshm library add ktz-autokali
bshm library use ktz-autokali
```

Добавить оболочки, если не добавлены, пересканировать библиотеку:
```
bshm shell add /usr/bin/bash
bshm shell add /usr/bin/python3
bshm shell add /usr/bin/msfconsole --name msfconsole --popen-args '["-q", "-x"]'
bshm library scan -f
```

Установить все необходимое:

```
bshm use install --item 1-7
```
После установки рекомендуется перелогиниться из-за docker

## Обновление
С недавних пор для совсем ленивых (для меня) присутствует скрипт с git pull, чтобы подгружать новые файлы без перехода в папку:

```
bshm use pull
```
Если модуля нет в вашей версии, зайдите в корневую папку библиотеки и сделайте `git pull` вручную