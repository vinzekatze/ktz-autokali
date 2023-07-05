# ktz-autokali

Библиотека [bashmator](https://github.com/vinzekatze/bashmator) для __kali linux__.

Потихоньку коплю тут необходимые мне скрипты.

## Установка

Добавить необходимые оболочки:
```
bashmator shell add /usr/bin/bash
bashmator shell add /usr/bin/python3
```

Скачать и добавить библиотеку:

```
git clone https://github.com/vinzekatze/ktz-autokali
bashmator library add "$(pwd)/ktz-autokali"
bashmator library use ktz-autokali
```