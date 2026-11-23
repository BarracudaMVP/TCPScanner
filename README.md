# portscan

`portscan` — Go-пакет для проверки доступности TCP-портов. Каждая проверка устанавливает обычное TCP-соединение и закрывает его сразу после успешного подключения. Пакет использует стандартную библиотеку Go.

## Использование

Пример проверяет несколько портов локальной машины. Вывод зависит от запущенных на ней служб.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "example.com/portscan"
)

func main() {
    scanner, err := portscan.New(portscan.Config{
        Concurrency:    32,
        ConnectTimeout: 500 * time.Millisecond,
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    results, err := scanner.Scan(ctx, []string{"127.0.0.1", "localhost"}, portscan.Ports{
        List:   []int{443},
        Ranges: []portscan.PortRange{{From: 8080, To: 8082}},
    })
    if err != nil {
        log.Fatal(err)
    }
    for result := range results {
        fmt.Printf("%s %s %d %s (%s)\n", result.Host, result.IP, result.Port, result.State, result.Duration)
        if result.Err != nil {
            log.Print(result.Err)
        }
    }
    if err := ctx.Err(); err != nil {
        log.Printf("контекст завершён: %v", err)
    }
}
```

Для примера в отдельном Go-модуле добавьте требование и замену на путь к клону репозитория. Сохраните код как `main.go` в модуле и запустите `go run .`.

```sh
go mod init example.com/portscan-demo
go mod edit '-require=example.com/portscan@v0.0.0'
go mod edit '-replace=example.com/portscan=/path/to/portscan'
```

## API и результаты

- `New(Config) (*Scanner, error)` принимает положительные `Concurrency` и `ConnectTimeout`. `Concurrency` ограничивает суммарное число активных подключений одного экземпляра, включая одновременные вызовы `Scan`. `ConnectTimeout` отсчитывается с начала TCP-подключения после разрешения DNS и ожидания слота.
- `(*Scanner).Scan(ctx, hosts, ports) (<-chan Result, error)` проверяет вход перед стартом. Ошибки входа и уже завершённый контекст возвращаются сразу. После старта результаты и ошибки отдельных проверок приходят через канал. Их порядок зависит от времени выполнения проверок.
- `Ports` объединяет `List []int` и `Ranges []PortRange`. Каждый `PortRange` включает `From` и `To`. Повторы учитываются один раз. Пустой набор, обратный диапазон и значения за пределами `1..65535` дают ошибку.
- `Result` содержит исходное написание `Host`, адрес `IP` типа `netip.Addr`, `Port`, `State`, `Duration` TCP-подключения и `Err` с исходной причиной ошибки.

Целями могут быть IPv4, IPv6 с зоной или без неё и ASCII DNS-имена. Передавайте отдельный хост без порта. IPv6 указывается без квадратных скобок. Пустые цели, некорректные адреса и неопределённые IP `0.0.0.0` и `::` дают ошибку входа. IPv4-mapped IPv6 приводятся к IPv4. Для повторов одной цели сохраняется первое входное написание. Регистр DNS-имени при сравнении игнорируется, а конечная точка сохраняется, поскольку влияет на разрешение имени.

DNS-имя разрешается один раз за вызов `Scan`. Если оно указывает на несколько IP, канал выдаёт результат для каждого уникального сочетания цели, IP и порта. Разные имена остаются отдельными целями. Если DNS не вернул пригодных адресов, для каждого порта этой цели выдаётся `error` с нулевыми `IP` и `Duration` и причиной в `Err`. Другие цели продолжают обрабатываться.

| `State` | Значение |
| --- | --- |
| `open` | Соединение установлено. `Err` равен `nil`. |
| `closed` | ОС вернула явный отказ в соединении. |
| `timeout` | Истёк лимит TCP-подключения или ОС вернула сетевой таймаут. |
| `unreachable` | ОС сообщила о недоступности узла или сети. |
| `canceled` | Подключение прервано отменой или дедлайном контекста вызова. |
| `error` | Другая ошибка подключения или ошибка DNS. |

## Чтение и отмена

Читайте канал до закрытия. Если прекращаете чтение раньше, вызовите `cancel()` перед выходом. Заполнение буфера при медленном чтении приостанавливает работу соответствующего вызова `Scan`. Установленные соединения к этому моменту уже закрыты, поэтому медленный читатель не удерживает слоты других вызовов.

```go
ctx, cancel := context.WithCancel(parent)
defer cancel()

results, err := scanner.Scan(ctx, hosts, ports)
if err != nil {
    return err
}
for result := range results {
    if result.State == portscan.StateOpen {
        cancel()
        break
    }
}
```

После отмены поток может содержать только часть результатов. Канал закрывается после завершения горутин вызова. `ctx.Err()` позволяет проверить состояние переданного контекста.

## Проверка

Используйте Go 1.25.5. На Windows для `-race` нужен MinGW-w64, у которого команда `gcc --print-file-name libsynchronization.a` возвращает полный путь. Если `gcc` находится вне `PATH`, задайте полный путь через `CC`. [Требования race detector](https://go.dev/doc/articles/race_detector#Requirements)

```powershell
$env:GOTOOLCHAIN = 'go1.25.5'
$env:CGO_ENABLED = '1'
$env:CC = 'gcc'
go version
go test -race ./...
```
