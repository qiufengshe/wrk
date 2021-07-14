// Copyright (C) 2012 - Will Glozer.  All rights reserved.

#include "wrk.h"
#include "script.h"
#include "main.h"

static struct config
{
    uint64_t connections;
    uint64_t duration;
    uint64_t threads;
    uint64_t timeout;
    uint64_t pipeline;
    bool delay;
    bool dynamic;
    bool latency;
    char *host;
    char *script;
    SSL_CTX *ctx;
} cfg;

static struct
{
    stats *latency;
    stats *requests;
} statistics;

//全局初始化sock,并给函数指针绑定对应的函数,这里绑定的都是http
//如果是https,在main函数中,会重新指向带ssl_*的函数
static struct sock sock = {
    .connect = sock_connect,
    .close = sock_close,
    .read = sock_read,
    .write = sock_write,
    .readable = sock_readable};

static struct http_parser_settings parser_settings = {
    .on_message_complete = response_complete};

static volatile sig_atomic_t stop = 0;

static void handler(int sig)
{
    stop = 1;
}

static void usage()
{
    printf("Usage: wrk <options> <url>                            \n"
           "  Options:                                            \n"
           "    -c, --connections <N>  Connections to keep open   \n"
           "    -d, --duration    <T>  Duration of test           \n"
           "    -t, --threads     <N>  Number of threads to use   \n"
           "                                                      \n"
           "    -s, --script      <S>  Load Lua script file       \n"
           "    -H, --header      <H>  Add header to request      \n"
           "        --latency          Print latency statistics   \n"
           "        --timeout     <T>  Socket/request timeout     \n"
           "    -v, --version          Print version details      \n"
           "                                                      \n"
           "  Numeric arguments may include a SI unit (1k, 1M, 1G)\n"
           "  Time arguments may include a time unit (2s, 2m, 2h)\n");
}

int main(int argc, char **argv)
{
    char *url, **headers = zmalloc(argc * sizeof(char *));
    struct http_parser_url parts = {};

    //根据参数 解析为URL和其他参数如-t 线程数量
    if (parse_args(&cfg, &url, &parts, headers, argc, argv))
    {
        usage();
        exit(1);
    }

    //根据URL 获取是否为http还是https
    //根据URL 获取请求宿主和端口号
    char *schema = copy_url_part(url, &parts, UF_SCHEMA);
    char *host = copy_url_part(url, &parts, UF_HOST);
    char *port = copy_url_part(url, &parts, UF_PORT);
    char *service = port ? port : schema;

    if (!strncmp("https", schema, 5))
    {
        //是https,使用对ssl进行初始化,加载证书相关
        if ((cfg.ctx = ssl_init()) == NULL)
        {
            fprintf(stderr, "unable to initialize SSL\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        sock.connect = ssl_connect;
        sock.close = ssl_close;
        sock.read = ssl_read;
        sock.write = ssl_write;
        sock.readable = ssl_readable;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, SIG_IGN);

    //根据参数持续时间,设置延迟时间
    statistics.latency = stats_alloc(cfg.timeout * 1000);
    statistics.requests = stats_alloc(MAX_THREAD_RATE_S);    //最大请求数量
    thread *threads = zcalloc(cfg.threads * sizeof(thread)); //根据参数 -t 10  分配线程数量所需的空间,返回thread结构体指针

    lua_State *L = script_create(cfg.script, url, headers); //根据url和请求头/lua脚本 加载lua环境
    if (!script_resolve(L, host, service))                  //处理lua脚本
    {
        char *msg = strerror(errno); //有错误,程序退出,不进行压测
        fprintf(stderr, "unable to connect to %s:%s %s\n", host, service, msg);
        exit(1);
    }

    cfg.host = host;

    //根据线程数量
    for (uint64_t i = 0; i < cfg.threads; i++)
    {
        thread *t = &threads[i];
        t->loop = aeCreateEventLoop(10 + cfg.connections * 3); //每个线程,创建一个事件循环,事件数是请求数量的3倍+10
        t->connections = cfg.connections / cfg.threads;        //连接数为请求数除以线程数

        t->L = script_create(cfg.script, url, headers);  //对每个线程,加载lua脚本
        script_init(L, t, argc - optind, &argv[optind]); //加载lua环境

        if (i == 0) //第一个线程,比较特殊
        {
            cfg.pipeline = script_verify_request(t->L);
            cfg.dynamic = !script_is_static(t->L);
            cfg.delay = script_has_delay(t->L);
            if (script_want_response(t->L))
            {
                parser_settings.on_header_field = header_field;
                parser_settings.on_header_value = header_value;
                parser_settings.on_body = response_body;
            }
        }

        //真正创建线程,传入回调函数thread_main 和线程参数t(thread结构)
        //每个线程执行thread_main(***重点***)
        if (!t->loop || pthread_create(&t->thread, NULL, &thread_main, t))
        {
            char *msg = strerror(errno);
            fprintf(stderr, "unable to create thread %" PRIu64 ": %s\n", i, msg);
            exit(2);
        }
    }

    //创建信号,指定信号处理函数handler
    struct sigaction sa = {
        .sa_handler = handler,
        .sa_flags = 0,
    };
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    //格式化持续时间,输出开始的消息
    char *time = format_time_s(cfg.duration);
    printf("Running %s test @ %s\n", time, url);
    printf("  %" PRIu64 " threads and %" PRIu64 " connections\n", cfg.threads, cfg.connections);

    uint64_t start = time_us();
    uint64_t complete = 0;
    uint64_t bytes = 0;
    errors errors = {0};

    //让主线程进行休眠,休眠时间为压测的持续时间
    sleep(cfg.duration);
    stop = 1;

    //等待所有工作线程执行结束,计算完整请求数 所有请求的大小
    //及错误的信息(连接数/读取数/写入数/超时时间/状态)
    for (uint64_t i = 0; i < cfg.threads; i++)
    {
        thread *t = &threads[i];
        pthread_join(t->thread, NULL);

        complete += t->complete;
        bytes += t->bytes;

        errors.connect += t->errors.connect;
        errors.read += t->errors.read;
        errors.write += t->errors.write;
        errors.timeout += t->errors.timeout;
        errors.status += t->errors.status;
    }

    uint64_t runtime_us = time_us() - start;
    long double runtime_s = runtime_us / 1000000.0;
    long double req_per_s = complete / runtime_s;
    long double bytes_per_s = bytes / runtime_s;

    if (complete / cfg.connections > 0)
    {
        int64_t interval = runtime_us / (complete / cfg.connections);
        stats_correct(statistics.latency, interval);
    }

    print_stats_header();
    print_stats("Latency", statistics.latency, format_time_us);
    print_stats("Req/Sec", statistics.requests, format_metric);
    if (cfg.latency)
        print_stats_latency(statistics.latency);

    char *runtime_msg = format_time_us(runtime_us);

    printf("  %" PRIu64 " requests in %s, %sB read\n", complete, runtime_msg, format_binary(bytes));
    if (errors.connect || errors.read || errors.write || errors.timeout)
    {
        printf("  Socket errors: connect %d, read %d, write %d, timeout %d\n",
               errors.connect, errors.read, errors.write, errors.timeout);
    }

    if (errors.status)
    {
        printf("  Non-2xx or 3xx responses: %d\n", errors.status);
    }

    printf("Requests/sec: %9.2Lf\n", req_per_s);
    printf("Transfer/sec: %10sB\n", format_binary(bytes_per_s));

    if (script_has_done(L))
    {
        script_summary(L, runtime_us, complete, bytes);
        script_errors(L, &errors);
        script_done(L, statistics.latency, statistics.requests);
    }

    return 0;
}

void *thread_main(void *arg)
{
    thread *thread = arg;

    char *request = NULL;
    size_t length = 0;

    if (!cfg.dynamic)
    {
        script_request(thread->L, &request, &length);
    }

    //给当前线程 根据连接数分配连接所需的内存
    thread->cs = zcalloc(thread->connections * sizeof(connection));
    connection *c = thread->cs;

    for (uint64_t i = 0; i < thread->connections; i++, c++)
    {
        c->thread = thread;
        c->ssl = cfg.ctx ? SSL_new(cfg.ctx) : NULL;
        c->request = request;
        c->length = length;
        c->delayed = cfg.delay;
        //根据线程结构体和连接对象,创建socket,设置为异步,使用socket进行连接,
        //并将socket绑定到thread结构体loop上
        connect_socket(thread, c);
    }

    aeEventLoop *loop = thread->loop;
    aeCreateTimeEvent(loop, RECORD_INTERVAL_MS, record_rate, thread, NULL); //给loop添加时间事件,设置回调函数record_rate

    thread->start = time_us(); //记录开始时间
    aeMain(loop);              //进入当前线程的loop事件,处理请求,

    aeDeleteEventLoop(loop);
    zfree(thread->cs);

    return NULL;
}

static int connect_socket(thread *thread, connection *c)
{
    struct addrinfo *addr = thread->addr;
    struct aeEventLoop *loop = thread->loop;
    int fd, flags;
    //创建socket
    fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK); //根据socket的句柄设置异步非阻塞

    if (connect(fd, addr->ai_addr, addr->ai_addrlen) == -1) //进行连接
    {
        if (errno != EINPROGRESS)
            goto error;
    }

    flags = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags)); //启动TCP_NODELAY，就意味着禁用了Nagle算法，允许小包的发送

    flags = AE_READABLE | AE_WRITABLE;
    if (aeCreateFileEvent(loop, fd, flags, socket_connected, c) == AE_OK) //根据socket的句柄,增加读/写事件,设置回调函数socket_connected
    {
        c->parser.data = c;
        c->fd = fd;
        return fd;
    }

error:
    thread->errors.connect++;
    close(fd);
    return -1;
}

static int reconnect_socket(thread *thread, connection *c)
{
    aeDeleteFileEvent(thread->loop, c->fd, AE_WRITABLE | AE_READABLE);
    sock.close(c);
    close(c->fd);
    return connect_socket(thread, c);
}

static int record_rate(aeEventLoop *loop, long long id, void *data)
{
    thread *thread = data;

    if (thread->requests > 0)
    {
        uint64_t elapsed_ms = (time_us() - thread->start) / 1000;
        uint64_t requests = (thread->requests / (double)elapsed_ms) * 1000;

        stats_record(statistics.requests, requests);

        thread->requests = 0;
        thread->start = time_us();
    }

    if (stop)
        aeStop(loop);

    return RECORD_INTERVAL_MS;
}

static int delay_request(aeEventLoop *loop, long long id, void *data)
{
    connection *c = data;
    c->delayed = false;
    aeCreateFileEvent(loop, c->fd, AE_WRITABLE, socket_writeable, c);
    return AE_NOMORE;
}

static int header_field(http_parser *parser, const char *at, size_t len)
{
    connection *c = parser->data;
    if (c->state == VALUE)
    {
        *c->headers.cursor++ = '\0';
        c->state = FIELD;
    }
    buffer_append(&c->headers, at, len);
    return 0;
}

static int header_value(http_parser *parser, const char *at, size_t len)
{
    connection *c = parser->data;
    if (c->state == FIELD)
    {
        *c->headers.cursor++ = '\0';
        c->state = VALUE;
    }
    buffer_append(&c->headers, at, len);
    return 0;
}

static int response_body(http_parser *parser, const char *at, size_t len)
{
    connection *c = parser->data;
    buffer_append(&c->body, at, len);
    return 0;
}

static int response_complete(http_parser *parser)
{
    connection *c = parser->data;
    thread *thread = c->thread;
    uint64_t now = time_us();
    int status = parser->status_code;

    thread->complete++;
    thread->requests++;

    if (status > 399)
    {
        thread->errors.status++;
    }

    if (c->headers.buffer)
    {
        *c->headers.cursor++ = '\0';
        script_response(thread->L, status, &c->headers, &c->body);
        c->state = FIELD;
    }

    if (--c->pending == 0)
    {
        if (!stats_record(statistics.latency, now - c->start))
        {
            thread->errors.timeout++;
        }
        c->delayed = cfg.delay;
        aeCreateFileEvent(thread->loop, c->fd, AE_WRITABLE, socket_writeable, c);
    }

    if (!http_should_keep_alive(parser))
    {
        reconnect_socket(thread, c);
        goto done;
    }

    http_parser_init(parser, HTTP_RESPONSE);

done:
    return 0;
}

static void socket_connected(aeEventLoop *loop, int fd, void *data, int mask)
{
    connection *c = data;

    switch (sock.connect(c, cfg.host))
    {
    case OK:
        break;
    case ERROR:
        goto error;
    case RETRY:
        return;
    }

    http_parser_init(&c->parser, HTTP_RESPONSE);
    c->written = 0;

    aeCreateFileEvent(c->thread->loop, fd, AE_READABLE, socket_readable, c);  //读事件
    aeCreateFileEvent(c->thread->loop, fd, AE_WRITABLE, socket_writeable, c); //写事件

    return;

error:
    c->thread->errors.connect++;
    reconnect_socket(c->thread, c);
}

static void socket_writeable(aeEventLoop *loop, int fd, void *data, int mask)
{
    connection *c = data;
    thread *thread = c->thread;

    if (c->delayed)
    {
        uint64_t delay = script_delay(thread->L);
        aeDeleteFileEvent(loop, fd, AE_WRITABLE);
        aeCreateTimeEvent(loop, delay, delay_request, c, NULL);
        return;
    }

    if (!c->written)
    {
        if (cfg.dynamic)
        {
            script_request(thread->L, &c->request, &c->length);
        }
        c->start = time_us();
        c->pending = cfg.pipeline;
    }

    char *buf = c->request + c->written;
    size_t len = c->length - c->written;
    size_t n;

    switch (sock.write(c, buf, len, &n))
    {
    case OK:
        break;
    case ERROR:
        goto error;
    case RETRY:
        return;
    }

    c->written += n;
    if (c->written == c->length)
    {
        c->written = 0;
        aeDeleteFileEvent(loop, fd, AE_WRITABLE);
    }

    return;

error:
    thread->errors.write++;
    reconnect_socket(thread, c);
}

static void socket_readable(aeEventLoop *loop, int fd, void *data, int mask)
{
    connection *c = data;
    size_t n;

    do
    {
        switch (sock.read(c, &n))
        {
        case OK:
            break;
        case ERROR:
            goto error;
        case RETRY:
            return;
        }

        if (http_parser_execute(&c->parser, &parser_settings, c->buf, n) != n)
            goto error;
        if (n == 0 && !http_body_is_final(&c->parser))
            goto error;

        c->thread->bytes += n;
    } while (n == RECVBUF && sock.readable(c) > 0);

    return;

error:
    c->thread->errors.read++;
    reconnect_socket(c->thread, c);
}

static uint64_t time_us()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (t.tv_sec * 1000000) + t.tv_usec;
}

static char *copy_url_part(char *url, struct http_parser_url *parts, enum http_parser_url_fields field)
{
    char *part = NULL;

    if (parts->field_set & (1 << field))
    {
        uint16_t off = parts->field_data[field].off;
        uint16_t len = parts->field_data[field].len;
        part = zcalloc(len + 1 * sizeof(char));
        memcpy(part, &url[off], len);
    }

    return part;
}

static struct option longopts[] = {
    {"connections", required_argument, NULL, 'c'},
    {"duration", required_argument, NULL, 'd'},
    {"threads", required_argument, NULL, 't'},
    {"script", required_argument, NULL, 's'},
    {"header", required_argument, NULL, 'H'},
    {"latency", no_argument, NULL, 'L'},
    {"timeout", required_argument, NULL, 'T'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}};

static int parse_args(struct config *cfg, char **url, struct http_parser_url *parts, char **headers, int argc, char **argv)
{
    char **header = headers;
    int c;

    memset(cfg, 0, sizeof(struct config));
    cfg->threads = 2;
    cfg->connections = 10;
    cfg->duration = 10;
    cfg->timeout = SOCKET_TIMEOUT_MS;

    while ((c = getopt_long(argc, argv, "t:c:d:s:H:T:Lrv?", longopts, NULL)) != -1)
    {
        switch (c)
        {
        case 't':
            if (scan_metric(optarg, &cfg->threads))
                return -1;
            break;
        case 'c':
            if (scan_metric(optarg, &cfg->connections))
                return -1;
            break;
        case 'd':
            if (scan_time(optarg, &cfg->duration))
                return -1;
            break;
        case 's':
            cfg->script = optarg;
            break;
        case 'H':
            *header++ = optarg;
            break;
        case 'L':
            cfg->latency = true;
            break;
        case 'T':
            if (scan_time(optarg, &cfg->timeout))
                return -1;
            cfg->timeout *= 1000;
            break;
        case 'v':
            printf("wrk %s [%s] ", VERSION, aeGetApiName());
            printf("Copyright (C) 2012 Will Glozer\n");
            break;
        case 'h':
        case '?':
        case ':':
        default:
            return -1;
        }
    }

    if (optind == argc || !cfg->threads || !cfg->duration)
        return -1;

    if (!script_parse_url(argv[optind], parts))
    {
        fprintf(stderr, "invalid URL: %s\n", argv[optind]);
        return -1;
    }

    if (!cfg->connections || cfg->connections < cfg->threads)
    {
        fprintf(stderr, "number of connections must be >= threads\n");
        return -1;
    }

    *url = argv[optind];
    *header = NULL;

    return 0;
}

static void print_stats_header()
{
    printf("  Thread Stats%6s%11s%8s%12s\n", "Avg", "Stdev", "Max", "+/- Stdev");
}

static void print_units(long double n, char *(*fmt)(long double), int width)
{
    char *msg = fmt(n);
    int len = strlen(msg), pad = 2;

    if (isalpha(msg[len - 1]))
        pad--;
    if (isalpha(msg[len - 2]))
        pad--;
    width -= pad;

    printf("%*.*s%.*s", width, width, msg, pad, "  ");

    free(msg);
}

static void print_stats(char *name, stats *stats, char *(*fmt)(long double))
{
    uint64_t max = stats->max;
    long double mean = stats_mean(stats);
    long double stdev = stats_stdev(stats, mean);

    printf("    %-10s", name);
    print_units(mean, fmt, 8);
    print_units(stdev, fmt, 10);
    print_units(max, fmt, 9);
    printf("%8.2Lf%%\n", stats_within_stdev(stats, mean, stdev, 1));
}

static void print_stats_latency(stats *stats)
{
    long double percentiles[] = {50.0, 75.0, 90.0, 99.0};
    printf("  Latency Distribution\n");
    for (size_t i = 0; i < sizeof(percentiles) / sizeof(long double); i++)
    {
        long double p = percentiles[i];
        uint64_t n = stats_percentile(stats, p);
        printf("%7.0Lf%%", p);
        print_units(n, format_time_us, 10);
        printf("\n");
    }
}
